package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.enums.AuthType;
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
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * 완전 일원화된 MfaFactorProcessingSuccessHandler
 * - ContextPersistence 완전 제거
 * - MfaStateMachineService만 사용
 * - State Machine 에서 직접 컨텍스트 로드 및 관리
 */
@Slf4j
public final class MfaFactorProcessingSuccessHandler extends AbstractMfaAuthenticationSuccessHandler {

    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;
    private final AuthUrlProvider authUrlProvider;

    public MfaFactorProcessingSuccessHandler(MfaStateMachineIntegrator mfaStateMachineIntegrator,
                                             MfaPolicyProvider mfaPolicyProvider,
                                             AuthResponseWriter responseWriter,
                                             ApplicationContext applicationContext,
                                             AuthContextProperties authContextProperties,
                                             MfaSessionRepository sessionRepository,
                                             TokenService tokenService,
                                             AuthUrlProvider authUrlProvider) {
        super(tokenService,responseWriter,sessionRepository,mfaStateMachineIntegrator,authContextProperties);
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.responseWriter = responseWriter;
        this.applicationContext = applicationContext;
        this.stateMachineIntegrator = mfaStateMachineIntegrator;
        this.sessionRepository = sessionRepository;
        this.authUrlProvider = authUrlProvider;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.debug("MFA Factor successfully processed for user: {} using {} repository",
                (((CustomUserDetails)authentication.getPrincipal())).getAccount().getUsername(), sessionRepository.getRepositoryType());

        // 1. FactorContext 로드 (SM 서비스는 내부적으로 락 사용 및 최신 상태 복원)
        FactorContext factorContext = stateMachineIntegrator.loadFactorContextFromRequest(request);
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), (((CustomUserDetails)authentication.getPrincipal())).getAccount().getUsername())) {
            handleInvalidContext(response, request, "MFA_FACTOR_SUCCESS_NO_CONTEXT",
                    "MFA 팩터 처리 성공 후 컨텍스트를 찾을 수 없거나 사용자가 일치하지 않습니다.", authentication);
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

        // Phase 2.1: 불필요한 중간 로드 제거 - sendEvent()가 이미 factorContext를 업데이트함
        // 3. 이벤트 처리 후 상태 확인 (컨텍스트는 sendEvent에서 이미 업데이트됨)

        // 4. 현재 상태 및 플래그에 따라 다음 단계 결정
        MfaState currentState = factorContext.getCurrentState();
        log.debug("State after FACTOR_VERIFIED_SUCCESS event: {} for session: {}", currentState, factorContext.getMfaSessionId());

        if (currentState == MfaState.FACTOR_VERIFICATION_COMPLETED) {
            // Phase 2: 다음 팩터 결정 필요 여부 확인 (읽기만)
            if (Boolean.TRUE.equals(factorContext.getAttribute("needsDetermineNextFactor"))) {
                log.debug("Sending DETERMINE_NEXT_FACTOR event for session: {}",
                         factorContext.getMfaSessionId());

                // Phase 2: State Machine에 이벤트 전송 (수정은 Action에서)
                boolean determined = stateMachineIntegrator.sendEvent(
                    MfaEvent.DETERMINE_NEXT_FACTOR, factorContext, request
                );

                if (!determined) {
                    log.error("Failed to determine next factor for session: {}",
                             factorContext.getMfaSessionId());
                    handleStateTransitionError(response, request, factorContext);
                    return;
                }
            }

            // Phase 2: 완료 여부 확인 (읽기만)
            log.debug("Sending CHECK_COMPLETION event for session: {}",
                     factorContext.getMfaSessionId());

            // Phase 2.2: State Machine에 이벤트 전송 및 에러 처리
            boolean completionChecked = false;
            try {
                completionChecked = stateMachineIntegrator.sendEvent(
                    MfaEvent.CHECK_COMPLETION, factorContext, request
                );

                if (!completionChecked) {
                    log.error("Failed to check completion for session: {}",
                             factorContext.getMfaSessionId());
                    handleStateTransitionError(response, request, factorContext);
                    return;
                }

            } catch (Exception e) {
                // Phase 2.2: Action에서 예외 발생 시 errorEventRecommendation 처리
                log.error("Exception during CHECK_COMPLETION for session: {}: {}",
                         factorContext.getMfaSessionId(), e.getMessage(), e);

                // 공통 메서드를 사용하여 errorEventRecommendation 처리
                processErrorEventRecommendation(factorContext, request, factorContext.getMfaSessionId());

                // 에러 응답 전송
                handleStateTransitionError(response, request, factorContext);
                return;
            }

            // Phase 2.3: CheckCompletionAction이 추천한 정상 이벤트 처리
            MfaEvent nextEvent = (MfaEvent) factorContext.getAttribute("nextEventRecommendation");
            if (nextEvent != null) {
                log.debug("Processing recommended event: {} for session: {}",
                         nextEvent, factorContext.getMfaSessionId());

                boolean eventSent = stateMachineIntegrator.sendEvent(nextEvent, factorContext, request);
                if (!eventSent) {
                    log.error("Failed to send recommended event: {} for session: {}",
                             nextEvent, factorContext.getMfaSessionId());
                    handleStateTransitionError(response, request, factorContext);
                    return;
                }

                // Clear the recommendation after processing
                factorContext.removeAttribute("nextEventRecommendation");
                log.debug("Recommended event {} processed successfully for session: {}",
                         nextEvent, factorContext.getMfaSessionId());
            }

            // Phase 2: 모든 이벤트 처리 후 최신 상태 로드
            FactorContext refreshedContext = stateMachineIntegrator.loadFactorContext(
                factorContext.getMfaSessionId()
            );

            if (refreshedContext == null) {
                handleInvalidContext(response, request, "CONTEXT_LOST_AFTER_POLICY",
                                   "정책 처리 후 컨텍스트 유실.", authentication);
                return;
            }

            factorContext = refreshedContext;
            log.debug("Context refreshed after policy processing. New state: {}",
                     factorContext.getCurrentState());
        }

        // 6. 최종 상태 확인 및 응답
        currentState = factorContext.getCurrentState();
        log.debug("Final state: {} for session: {}", currentState, factorContext.getMfaSessionId());

        // 7. 상태에 따른 응답 처리
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

            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);

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

            responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);

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
        responseBody.put("nextStepUrl", nextStepUrl);
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

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "SESSION_NOT_FOUND", "MFA 세션을 찾을 수 없습니다.", request.getRequestURI(), errorResponse);
    }

    /**
     * 개선: Repository 패턴을 통한 무효한 컨텍스트 처리 (HttpSession 직접 접근 제거)
     */
    private void handleInvalidContext(HttpServletResponse response, HttpServletRequest request,
                                      String errorCode, String logMessage, @Nullable Authentication authentication) throws IOException {
        log.warn("MFA Factor Processing Success using {} repository: Invalid FactorContext. Message: {}. User from auth: {}",
                sessionRepository.getRepositoryType(), logMessage,
                (authentication != null ? (((CustomUserDetails)authentication.getPrincipal())).getAccount().getUsername(): "UnknownUser"));

        // 개선: Repository를 통한 세션 정리 (HttpSession 직접 접근 제거)
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

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, errorCode,
                "MFA 세션 컨텍스트 오류: " + logMessage, request.getRequestURI(), errorResponse);
    }

    // Phase 1.2: syncContextFromStateMachine() 제거 - Dead Code (미사용 메서드)
    // Single Source of Truth 패턴에서는 State Machine에서만 상태를 관리하므로 불필요

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

        // SYSTEM_ERROR 이벤트 전송
        stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, ctx, request);

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "STATE_TRANSITION_ERROR", "상태 전이 오류가 발생했습니다.",
                request.getRequestURI());
    }

    @Nullable
    private AuthenticationFlowConfig findMfaFlowConfig(String flowTypeName) {
        if (!StringUtils.hasText(flowTypeName)) {
            return null;
        }

        PlatformConfig platformConfig;
        try {
            platformConfig = applicationContext.getBean(PlatformConfig.class);
        } catch (Exception e) {
            log.error("PlatformConfig bean not found in ApplicationContext", e);
            return null;
        }

        if (platformConfig == null || platformConfig.getFlows() == null) {
            log.error("PlatformConfig or its flows list is null");
            return null;
        }

        List<AuthenticationFlowConfig> matchingFlows = platformConfig.getFlows().stream()
                .filter(flow -> flowTypeName.equalsIgnoreCase(flow.getTypeName()))
                .collect(Collectors.toList());

        if (matchingFlows.isEmpty()) {
            log.warn("No AuthenticationFlowConfig found with typeName '{}'", flowTypeName);
            return null;
        }

        if (matchingFlows.size() > 1) {
            log.error("CRITICAL: Multiple AuthenticationFlowConfigs found for typeName '{}'. Using first one.",
                    flowTypeName);
        }

        return matchingFlows.get(0);
    }
    private void handleConfigError(HttpServletResponse response, HttpServletRequest request,
                                   FactorContext ctx, String message) throws IOException {
        log.error("Configuration error for flow '{}': {}", ctx.getFlowTypeName(), message);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "MFA_FLOW_CONFIG_ERROR", message, request.getRequestURI());

        // State Machine 정리
        try {
            stateMachineIntegrator.releaseStateMachine(ctx.getMfaSessionId());
        } catch (Exception e) {
            log.warn("Failed to release State Machine session after config error: {}", ctx.getMfaSessionId(), e);
        }
    }

    private void handleGenericError(HttpServletResponse response, HttpServletRequest request,
                                    FactorContext ctx, String message) throws IOException {
        log.error("Generic error during MFA factor processing for user {}: {}", ctx.getUsername(), message);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "MFA_PROCESSING_ERROR", message, request.getRequestURI());

        // State Machine 정리
        try {
            stateMachineIntegrator.releaseStateMachine(ctx.getMfaSessionId());
        } catch (Exception e) {
            log.warn("Failed to release State Machine session after generic error: {}", ctx.getMfaSessionId(), e);
        }
    }
}
