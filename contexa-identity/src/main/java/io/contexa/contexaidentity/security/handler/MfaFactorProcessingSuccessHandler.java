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
            // 이벤트가 수락되지 않은 경우, MfaStateMachineServiceImpl.sendEvent 에서
            // factorContext의 상태를 현재 SM 상태와 동기화하고 저장했을 것이므로, 그 상태를 기반으로 오류 처리.
            // 또는, sendEvent가 예외를 던지도록 하여 try-catch로 처리.
            // 여기서는 FactorContext를 다시 로드하여 최신 상태 확인.
            FactorContext currentContextAfterEvent = stateMachineIntegrator.loadFactorContext(factorContext.getMfaSessionId());
            handleStateTransitionError(response, request, currentContextAfterEvent != null ? currentContextAfterEvent : factorContext);
            return;
        }

        // 3. 이벤트 처리 후, SM 내부의 Action에 의해 FactorContext가 변경되었을 수 있으므로 최신 FactorContext를 다시 로드.
        FactorContext updatedFactorContext = stateMachineIntegrator.loadFactorContext(factorContext.getMfaSessionId());
        if (updatedFactorContext == null) {
            handleInvalidContext(response, request, "CONTEXT_LOST_AFTER_EVENT", "이벤트 처리 후 컨텍스트 유실.", authentication);
            return;
        }
        factorContext = updatedFactorContext; // 핸들러의 factorContext를 최신으로 업데이트

        // 4. 현재 상태 및 플래그에 따라 다음 단계 결정
        MfaState currentState = factorContext.getCurrentState();
        log.debug("State after FACTOR_VERIFIED_SUCCESS event: {} for session: {}", currentState, factorContext.getMfaSessionId());

        if (currentState == MfaState.FACTOR_VERIFICATION_COMPLETED) {
            // Action에서 설정한 needsDetermineNextFactor 플래그 확인
            if (Boolean.TRUE.equals(factorContext.getAttribute("needsDetermineNextFactor"))) {
                factorContext.removeAttribute("needsDetermineNextFactor"); // 플래그 사용 후 제거
                // 제거 후 FactorContext를 한번 저장해주는 것이 좋음 (버전업 및 상태 일관성)
                stateMachineIntegrator.saveFactorContext(factorContext); // MfaStateMachineServiceImpl.saveFactorContext는 버전업 및 persist 포함

                mfaPolicyProvider.determineNextFactorToProcess(factorContext); // 이 내부에서 필요한 이벤트 전송 및 FactorContext 업데이트/저장 가정

                // PolicyProvider가 FactorContext를 변경했으므로 다시 로드
                factorContext = stateMachineIntegrator.loadFactorContext(factorContext.getMfaSessionId());
                if (factorContext == null) {
                    // 여기서 request와 authentication 객체가 필요합니다.
                    // 해당 객체들을 현재 메서드의 파라미터로 받거나, 클래스 필드로 가지고 있어야 합니다.
                    // 아래는 예시이며, 실제 사용 가능한 변수로 대체해야 합니다.
                    // HttpServletRequest request = ...; // 현재 요청 객체
                    // Authentication authentication = ...; // 현재 인증 객체
                    handleInvalidContext(response, request, "CONTEXT_LOST_AFTER_EVENT", "이벤트 처리 후 컨텍스트 유실.", authentication);
                    return; // 오류 발생 시 추가 진행 중단
                }
            }

            AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig(factorContext.getFlowTypeName());
            if (mfaFlowConfig != null) {
                mfaPolicyProvider.checkAllFactorsCompleted(factorContext, mfaFlowConfig); // 이 내부에서 이벤트 전송 및 FactorContext 업데이트/저장 가정

                // PolicyProvider가 FactorContext를 변경했으므로 다시 로드
                factorContext = stateMachineIntegrator.loadFactorContext(factorContext.getMfaSessionId());
                if (factorContext == null) {
                    // 여기서 request와 authentication 객체가 필요합니다.
                    // 해당 객체들을 현재 메서드의 파라미터로 받거나, 클래스 필드로 가지고 있어야 합니다.
                    // 아래는 예시이며, 실제 사용 가능한 변수로 대체해야 합니다.
                    // HttpServletRequest request = ...; // 현재 요청 객체
                    // Authentication authentication = ...; // 현재 인증 객체
                    handleInvalidContext(response, request, "CONTEXT_LOST_AFTER_EVENT", "이벤트 처리 후 컨텍스트 유실.", authentication);
                    return; // 오류 발생 시 추가 진행 중단
                }
            }
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
                    request.getContextPath() + authUrlProvider.getMfaSelectFactorUi(),
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

    /**
     * State Machine 에서 컨텍스트 동기화
     */
    private void syncContextFromStateMachine(FactorContext target, FactorContext source) {
        if (target.getCurrentState() != source.getCurrentState()) {
            target.changeState(source.getCurrentState());
        }

        while (target.getVersion() < source.getVersion()) {
            target.incrementVersion();
        }

        target.setCurrentProcessingFactor(source.getCurrentProcessingFactor());
        target.setCurrentStepId(source.getCurrentStepId());
        target.setMfaRequiredAsPerPolicy(source.isMfaRequiredAsPerPolicy());

        log.debug("Context synchronized from unified State Machine: sessionId={}, version={}, state={}",
                target.getMfaSessionId(), target.getVersion(), target.getCurrentState());
    }

    private String determineNextFactorUrl(AuthType factorType, HttpServletRequest request) {
        return switch (factorType) {
            case OTT -> request.getContextPath() +
                    authUrlProvider.getOttRequestCodeUi();
            case PASSKEY -> request.getContextPath() +
                    authUrlProvider.getPasskeyChallengeUi();
            default -> {
                log.error("Unsupported MFA factor type: {}", factorType);
                yield request.getContextPath() + authUrlProvider.getMfaSelectFactorUi();
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
