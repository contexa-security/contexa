package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.domain.dto.UserDto;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.filter.RestAuthenticationToken;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.CustomUserDetails;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 완전 일원화된 MfaFactorProcessingSuccessHandler
 * - ContextPersistence 완전 제거
 * - MfaStateMachineService만 사용
 * - State Machine 에서 직접 컨텍스트 로드 및 관리
 */
@Slf4j
public final class MfaFactorProcessingSuccessHandler extends AbstractMfaAuthenticationSuccessHandler {

    private final AuthResponseWriter responseWriter;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;
    private final AuthUrlProvider authUrlProvider;
    private final ModelMapper modelMapper;
    // Phase 3: MfaPolicyProvider 제거 - 모든 비즈니스 로직은 DetermineNextFactorAction에서 처리

    public MfaFactorProcessingSuccessHandler(MfaStateMachineIntegrator mfaStateMachineIntegrator,
                                             AuthResponseWriter responseWriter,
                                             ApplicationContext applicationContext, // 파라미터는 유지 (DI)
                                             AuthContextProperties authContextProperties,
                                             MfaSessionRepository sessionRepository,
                                             TokenService tokenService,
                                             AuthUrlProvider authUrlProvider,
                                             ModelMapper modelMapper) {
        super(tokenService,responseWriter,sessionRepository,mfaStateMachineIntegrator,authContextProperties);
        this.responseWriter = responseWriter;
        this.stateMachineIntegrator = mfaStateMachineIntegrator;
        this.sessionRepository = sessionRepository;
        this.authUrlProvider = authUrlProvider;
        this.modelMapper = modelMapper;
        // applicationContext: 파라미터로 받지만 필드에 저장하지 않음 (현재 미사용)
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        Authentication converterAuthentication = replaceWithSerializableAuthentication(authentication);
        if (converterAuthentication != null) {
            SecurityContextHolder.getContext().setAuthentication(converterAuthentication);
            log.debug("Authentication replaced with serializable UserDto principal for user: {}",
                    getPrincipalUsername(converterAuthentication));
        }

        FactorContext factorContext = (FactorContext) request.getAttribute("io.contexa.mfa.FactorContext");

        if (factorContext == null) {
            log.debug("FactorContext not found in request attribute, loading from State Machine");
            factorContext = stateMachineIntegrator.loadFactorContextFromRequest(request);
        } else {
            log.debug("FactorContext retrieved from request attribute for session: {}", factorContext.getMfaSessionId());
        }

        String username = getPrincipalUsername(converterAuthentication);
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), username)) {
            handleInvalidContext(response, request,
                    converterAuthentication);
            return;
        }

        if (!sessionRepository.existsSession(factorContext.getMfaSessionId())) { // 세션 유효성 검증
            log.warn("MFA session {} not found in {} repository during factor processing success",
                    factorContext.getMfaSessionId(), sessionRepository.getRepositoryType());
            handleSessionNotFound(response, request, factorContext);
            return;
        }

        // 2. "팩터 검증 성공" 이벤트 전송.
        // MfaStateMachineServiceImpl.sendEvent 내부에서 FactorContext 업데이트 및 영속화가 이루어짐.
        // sendEvent는 업데이트된 FactorContext를 반환하도록 수정하거나, 여기서는 eventAccepted만 확인.
        boolean eventAccepted = stateMachineIntegrator.sendEvent(
                MfaEvent.FACTOR_VERIFIED_SUCCESS, factorContext, request);

        if (!eventAccepted) {
            // 이벤트가 거부되면 State Machine이 상태를 변경하지 않으므로 기존 context 사용
            handleStateTransitionError(response, request, factorContext);
            return;
        }

        // 3. 현재 상태 및 플래그에 따라 다음 단계 결정
        MfaState currentState = factorContext.getCurrentState();
        log.debug("State after FACTOR_VERIFIED_SUCCESS event: {} for session: {}", currentState, factorContext.getMfaSessionId());

        if (currentState == MfaState.FACTOR_VERIFICATION_COMPLETED) {
            // Phase 3: DetermineNextFactorAction이 완료 체크 및 다음 이벤트 결정
            log.debug("Sending DETERMINE_NEXT_FACTOR event for session: {}", factorContext.getMfaSessionId());

            boolean determined = stateMachineIntegrator.sendEvent(MfaEvent.DETERMINE_NEXT_FACTOR, factorContext, request);

            if (!determined) {
                log.error("Failed to determine next factor for session: {}", factorContext.getMfaSessionId());
                handleStateTransitionError(response, request, factorContext);
                return;
            }

            // Phase 4: Action이 설정한 추천 이벤트 전송
            MfaEvent nextEvent = (MfaEvent) factorContext.getAttribute(FactorContextAttributes.StateControl.NEXT_EVENT_RECOMMENDATION);
            if (nextEvent != null) {
                log.debug("Processing recommended event: {} for session: {}",
                         nextEvent, factorContext.getMfaSessionId());

                // FACTOR_SELECTED 이벤트일 때 currentProcessingFactor를 MessageHeader로 전달
                boolean eventSent;
                if (nextEvent == MfaEvent.FACTOR_SELECTED && factorContext.getCurrentProcessingFactor() != null) {
                    Map<String, Object> headers = new HashMap<>();
                    headers.put("selectedFactor", factorContext.getCurrentProcessingFactor().name());
                    log.debug("Adding selectedFactor header: {} for session: {}",
                             factorContext.getCurrentProcessingFactor().name(), factorContext.getMfaSessionId());
                    eventSent = stateMachineIntegrator.sendEvent(nextEvent, factorContext, request, headers);
                } else {
                    eventSent = stateMachineIntegrator.sendEvent(nextEvent, factorContext, request);
                }

                if (!eventSent) {
                    log.error("Failed to send recommended event: {} for session: {}", nextEvent, factorContext.getMfaSessionId());
                    handleStateTransitionError(response, request, factorContext);
                    return;
                }

                // Clear the recommendation after processing
                factorContext.removeAttribute("nextEventRecommendation");
                log.debug("Recommended event {} processed successfully for session: {}", nextEvent, factorContext.getMfaSessionId());
            }

        }

        // 5. 최종 상태 확인 및 응답
        currentState = factorContext.getCurrentState();
        log.debug("Final state: {} for session: {}", currentState, factorContext.getMfaSessionId());

        // 6. 상태에 따른 응답 처리
        if (currentState == MfaState.ALL_FACTORS_COMPLETED || currentState == MfaState.MFA_SUCCESSFUL) {
            // 모든 팩터 완료 - 최종 성공 처리
            log.info("All required MFA factors completed for user: {}", factorContext.getUsername());
            handleFinalAuthenticationSuccess(request, response,
                    factorContext.getPrimaryAuthentication(), factorContext);

        } else if (currentState == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION &&
                factorContext.getCurrentProcessingFactor() != null) {
            // 다음 팩터가 결정됨 - 챌린지로 이동
            AuthType nextFactor = factorContext.getCurrentProcessingFactor();
            log.info("Next factor determined: {} for user: {}", nextFactor, factorContext.getUsername());

            String nextUrl = determineNextFactorUrl(nextFactor, request);
            // 현재 팩터에 따라 단계 결정 (OTT=2, PASSKEY=3)
            int currentStep = (nextFactor == AuthType.OTT) ? 2 : 3;
            Map<String, Object> responseBody = createMfaContinueResponse(
                    "다음 인증 단계로 진행합니다: " + nextFactor.name(),
                    factorContext, nextUrl, currentStep);
            responseBody.put("nextFactorType", nextFactor.name());

            if (!response.isCommitted()) {
                responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
            } else {
                log.warn("Response already committed for user: {}, cannot write MFA continue response",
                        factorContext.getUsername());
            }

        } else if (currentState == MfaState.AWAITING_FACTOR_SELECTION) {
            // 수동 선택 필요 (정책상 다음 팩터가 필요하지만 자동 선택 불가)
            log.info("Manual factor selection required for user: {}", factorContext.getUsername());

            Map<String, Object> responseBody = createMfaContinueResponse(
                    "인증 수단을 선택해주세요.",
                    factorContext,
                    request.getContextPath() + authUrlProvider.getMfaSelectFactor(),
                    2  // Factor 선택 단계 (OTT 또는 Passkey 선택 중)
            );
            // DSL 정의 사용 가능한 팩터를 상세 정보로 변환
            java.util.List<Map<String, Object>> factorDetails = factorContext.getAvailableFactors().stream()
                    .map(authType -> createFactorDetail(authType.name()))
                    .toList();
            responseBody.put("availableFactors", factorDetails);

            if (!response.isCommitted()) {
                responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
            } else {
                log.warn("Response already committed for user: {}, cannot write factor selection response",
                        factorContext.getUsername());
            }

        } else {
            // 예상치 못한 상태
            log.error("Unexpected state {} after factor verification", currentState);
            handleGenericError(response, request, factorContext,
                    "예상치 못한 상태: " + currentState);
        }
    }

    /**
     * MFA 계속 진행 응답 생성 (progress 정보 포함)
     *
     * @param currentStep 현재 단계 (2: OTT, 3: Passkey)
     */
    private Map<String, Object> createMfaContinueResponse(String message, FactorContext factorContext, String nextStepUrl, int currentStep) {
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", "MFA_CONTINUE");
        responseBody.put("message", message);
        responseBody.put("authenticated", false); // MFA_CONTINUE는 중간 단계
        responseBody.put("nextStepUrl", nextStepUrl);
        responseBody.put("nextStepId", factorContext.getCurrentStepId()); // X-MFA-Step-Id 헤더용
        responseBody.put("mfaSessionId", factorContext.getMfaSessionId());
        responseBody.put("progress", createProgressInfo(currentStep, 3)); // 총 3단계

        return responseBody;
    }

    /**
     * 개선: Repository 패턴을 통한 세션 미발견 처리
     */
    private void handleSessionNotFound(HttpServletResponse response, HttpServletRequest request,
                                       FactorContext factorContext) throws IOException {
        log.warn("Session not found in {} repository during factor processing success: {}",
                sessionRepository.getRepositoryType(), factorContext.getMfaSessionId());

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("mfaSessionId", factorContext.getMfaSessionId());

        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "SESSION_NOT_FOUND", "MFA 세션을 찾을 수 없습니다.", request.getRequestURI(), errorResponse);
        } else {
            log.warn("Response already committed, cannot write SESSION_NOT_FOUND error for session: {}",
                    factorContext.getMfaSessionId());
        }
    }

    /**
     * 개선: Repository 패턴을 통한 무효한 컨텍스트 처리 (HttpSession 직접 접근 제거)
     */
    private void handleInvalidContext(HttpServletResponse response, HttpServletRequest request,
                                      @Nullable Authentication authentication) throws IOException {
        log.warn("MFA Factor Processing Success using {} repository: Invalid FactorContext. Message: {}. User from auth: {}",
                sessionRepository.getRepositoryType(), "MFA 팩터 처리 성공 후 컨텍스트를 찾을 수 없거나 사용자가 일치하지 않습니다.",
                (authentication != null ? authentication.getName(): "UnknownUser"));

        String oldSessionId = sessionRepository.getSessionId(request);
        if (oldSessionId != null) {
            try {
                stateMachineIntegrator.releaseStateMachine(oldSessionId);
                sessionRepository.removeSession(oldSessionId, request, null);
            } catch (Exception e) {
                log.warn("Failed to release invalid session using {} repository: {}",
                        sessionRepository.getRepositoryType(), oldSessionId, e);
            }
        }

        Map<String, Object> errorResponse = new HashMap<>();

        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "MFA_FACTOR_SUCCESS_NO_CONTEXT",
                    "MFA 세션 컨텍스트 오류: " + "MFA 팩터 처리 성공 후 컨텍스트를 찾을 수 없거나 사용자가 일치하지 않습니다.", request.getRequestURI(), errorResponse);
        } else {
            log.warn("Response already committed, cannot write INVALID_CONTEXT error: {}", "MFA_FACTOR_SUCCESS_NO_CONTEXT");
        }
    }

    private String determineNextFactorUrl(AuthType factorType, HttpServletRequest request) {
        return switch (factorType) {
            case OTT -> request.getContextPath() +
                    authUrlProvider.getOttRequestCodeUi();
            case PASSKEY -> request.getContextPath() +
                    authUrlProvider.getPasskeyChallengeUi();
            default -> {
                log.error("Unsupported MFA factor type: {}", factorType);
                yield request.getContextPath() + authUrlProvider.getMfaSelectFactor();
            }
        };
    }

    private void handleStateTransitionError(HttpServletResponse response, HttpServletRequest request,
                                            FactorContext ctx) throws IOException {
        log.error("State Machine transition error for session: {}", ctx.getMfaSessionId());
        stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, ctx, request);

        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "STATE_TRANSITION_ERROR", "상태 전이 오류가 발생했습니다.",
                    request.getRequestURI());
        } else {
            log.warn("Response already committed, cannot write STATE_TRANSITION_ERROR for session: {}",
                    ctx.getMfaSessionId());
        }
    }

    private void handleGenericError(HttpServletResponse response, HttpServletRequest request,
                                    FactorContext ctx, String message) throws IOException {
        log.error("Generic error during MFA factor processing for user {}: {}", ctx.getUsername(), message);

        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "MFA_PROCESSING_ERROR", message, request.getRequestURI());
        } else {
            log.warn("Response already committed, cannot write MFA_PROCESSING_ERROR for user: {}",
                    ctx.getUsername());
        }
        try {
            stateMachineIntegrator.releaseStateMachine(ctx.getMfaSessionId());
        } catch (Exception e) {
            log.warn("Failed to release State Machine session after generic error: {}", ctx.getMfaSessionId(), e);
        }
    }

    /**
     * Authentication에서 username 추출 (CustomUserDetails 또는 UserDto 모두 지원)
     */
    private String getPrincipalUsername(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof CustomUserDetails customUserDetails) {
            return customUserDetails.getAccount().getUsername();
        } else if (principal instanceof UserDto userDto) {
            return userDto.getUsername();
        } else {
            return principal.toString();
        }
    }

    /**
     * CustomUserDetails Principal을 UserDto로 교체하여 Redis 직렬화 가능한 Authentication 생성
     *
     * Spring Security의 AbstractAuthenticationProcessingFilter가 successHandler 호출 전에
     * SecurityContext에 Authentication을 저장하지만, Spring Session은 response.flush() 시점에
     * SecurityContext를 Redis에 직렬화합니다.
     *
     * OneTimeTokenAuthenticationToken의 Principal은 CustomUserDetails(Users 엔티티 포함)이므로
     * Redis 직렬화 시 NotSerializableException이 발생합니다.
     *
     * 이 메서드는 response.flush() 전에 Authentication을 UserDto 기반으로 교체하여
     * Redis 직렬화 안전성을 보장합니다.
     *
     * @param authentication 원본 Authentication (OneTimeTokenAuthenticationToken with CustomUserDetails)
     * @return UserDto Principal을 가진 RestAuthenticationToken, 교체 불필요 시 null
     */
    private Authentication replaceWithSerializableAuthentication(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof PublicKeyCredentialUserEntity entity) {
            try {
                return RestAuthenticationToken.authenticated(entity.getName(), authentication.getAuthorities());

            } catch (Exception e) {
                log.error("Failed to replace Authentication with serializable version. " +
                         "CustomUserDetails will remain in SecurityContext (may cause Redis serialization error)", e);
                return null;
            }
        }
        return authentication;
    }
}
