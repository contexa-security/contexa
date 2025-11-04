package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.domain.dto.UserDto;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 완전 일원화된 UnifiedAuthenticationSuccessHandler
 * - ContextPersistence 완전 제거
 * - MfaStateMachineService만 사용
 * - State Machine 에서 직접 컨텍스트 로드 및 관리
 */
@Slf4j

public final class PrimaryAuthenticationSuccessHandler extends AbstractMfaAuthenticationSuccessHandler  {

    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthResponseWriter responseWriter;
    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;
    private final AuthUrlProvider authUrlProvider;
    private final ApplicationContext applicationContext;

    public PrimaryAuthenticationSuccessHandler(MfaPolicyProvider mfaPolicyProvider, TokenService tokenService, AuthResponseWriter responseWriter, AuthContextProperties authContextProperties, ApplicationContext applicationContext, MfaStateMachineIntegrator stateMachineIntegrator, MfaSessionRepository sessionRepository, AuthUrlProvider authUrlProvider) {
        super(tokenService,responseWriter,sessionRepository,stateMachineIntegrator,authContextProperties);
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.responseWriter = responseWriter;
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.sessionRepository = sessionRepository;
        this.authUrlProvider = authUrlProvider;
        this.applicationContext = applicationContext;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        log.info("Processing authentication success for user: {}", ((UserDto) authentication.getPrincipal()).getUsername());

        String username = ((UserDto) authentication.getPrincipal()).getUsername();
        String mfaSessionId = sessionRepository.getSessionId(request); // 필터에서 저장한 세션 ID 가져오기
        if (mfaSessionId == null) {
            handleInvalidContext(response, request, "SESSION_ID_NOT_FOUND", "MFA 세션 ID를 찾을 수 없습니다.", authentication);
            return;
        }

        FactorContext factorContext = stateMachineIntegrator.loadFactorContext(mfaSessionId); // SM 에서 최신 FactorContext 로드
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), ((UserDto)authentication.getPrincipal()).getUsername())) {
            log.error("Invalid FactorContext or username mismatch after primary authentication.");
            handleInvalidContext(response, request, "INVALID_CONTEXT", "인증 컨텍스트가 유효하지 않거나 사용자 정보가 일치하지 않습니다.", authentication);
            return;
        }

        // Phase 2: PolicyProvider에서 읽기 전용 평가
        MfaDecision decision = mfaPolicyProvider.evaluateInitialMfaRequirement(factorContext);

        // Phase 2.2: MfaDecision을 담아서 PRIMARY_AUTH_SUCCESS 이벤트 전송 및 에러 처리
        Map<String, Object> headers = new HashMap<>();
        headers.put("mfaDecision", decision);

        try {
            boolean initialized = stateMachineIntegrator.sendEvent(MfaEvent.PRIMARY_AUTH_SUCCESS, factorContext, request, headers);

            if (!initialized) {
                log.error("Failed to initialize MFA for session: {}", mfaSessionId);
                handleConfigError(response, request, factorContext, "MFA 초기화 실패.");
                return;
            }

        } catch (Exception e) {
            // Phase 2.2: Action에서 예외 발생 시 errorEventRecommendation 처리
            log.error("Exception during PRIMARY_AUTH_SUCCESS for session: {}: {}",
                     mfaSessionId, e.getMessage(), e);

            // 공통 메서드를 사용하여 errorEventRecommendation 처리
            processErrorEventRecommendation(factorContext, request, mfaSessionId);

            handleConfigError(response, request, factorContext, "MFA 초기화 중 오류 발생.");
            return;
        }

        // AI가 인증을 차단한 경우 처리
        if (decision.isBlocked()) {
            log.warn("Authentication blocked by AI policy for user: {} - Reason: {}",
                    factorContext.getUsername(), decision.getReason());

            // Context 재로드
            FactorContext blockedContext = stateMachineIntegrator.loadFactorContext(mfaSessionId);
            if (blockedContext == null) {
                handleInvalidContext(response, request, "CONTEXT_LOST", "MFA 처리 중 컨텍스트 유실.", authentication);
                return;
            }

            // 차단 응답 처리
            handleAuthenticationBlocked(request, response, blockedContext);
            return;
        }

        // Phase 2: 다음 이벤트 결정 및 전송
        boolean nextEventSent = sendNextMfaEvent(decision, mfaSessionId, request);
        if (!nextEventSent) {
            log.error("Failed to send next MFA event for session: {}", mfaSessionId);
            handleConfigError(response, request, factorContext, "MFA 이벤트 전송 실패.");
            return;
        }

        // Context 최종 로드
        FactorContext finalFactorContext = stateMachineIntegrator.loadFactorContext(mfaSessionId);
        if (finalFactorContext == null) {
            handleInvalidContext(response, request, "CONTEXT_LOST", "MFA 처리 중 컨텍스트 유실.", authentication);
            return;
        }

        // 4. 최종 상태에 따른 응답 생성
        MfaState currentState = finalFactorContext.getCurrentState();

        switch (currentState) {
            case MFA_NOT_REQUIRED, MFA_SUCCESSFUL:
                log.info("MFA not required for user: {}. Proceeding with final authentication success.", username);
                handleFinalAuthenticationSuccess(request, response, authentication, finalFactorContext);
                break;

            case AWAITING_FACTOR_SELECTION:
                log.info("MFA required for user: {}. State: AWAITING_FACTOR_SELECTION", username);
                handleFactorSelectionRequired(request, response, finalFactorContext);
                break;

            case FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION:
                log.info("MFA required for user: {}. Proceeding directly to challenge", username);
                handleDirectChallenge(request, response, finalFactorContext);
                break;

            case PRIMARY_AUTHENTICATION_COMPLETED:
                log.error("State remained PRIMARY_AUTHENTICATION_COMPLETED for user: {}. Next event may have failed.", username);
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, factorContext, request);
                handleConfigError(response, request, finalFactorContext, "MFA 초기화 후 다음 단계로 전이되지 않았습니다.");
                break;

            default:
                log.error("Unexpected FactorContext state ({}) for user {} after policy evaluation",
                        currentState, username);
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, factorContext, request);
                handleConfigError(response, request, finalFactorContext, "MFA 처리 중 예상치 못한 상태입니다.");
        }
    }

    private void handleFactorSelectionRequired(HttpServletRequest request, HttpServletResponse response,
                                               FactorContext factorContext) throws IOException {
        Map<String, Object> responseBody = createMfaResponseBody(
                "MFA_REQUIRED_SELECT_FACTOR",
                "추가 인증이 필요합니다. 인증 수단을 선택해주세요.",
                factorContext,
                request.getContextPath() + authUrlProvider.getMfaSelectFactorUi(),
                2  // Primary 완료, OTT/Passkey 선택 단계
        );
        // DSL 사용 가능한 팩터를 상세 정보로 변환
        java.util.List<Map<String, Object>> factorDetails = factorContext.getAvailableFactors().stream()
                .map(authType -> createFactorDetail(authType.name()))
                .toList();
        responseBody.put("availableFactors", factorDetails);
        responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
    }

    private void handleDirectChallenge(HttpServletRequest request, HttpServletResponse response,
                                       FactorContext factorContext) throws IOException {
        AuthType nextFactor = factorContext.getCurrentProcessingFactor();
        String nextUiPageUrl = determineChalllengeUrl(factorContext, request);

        Map<String, Object> responseBody = createMfaResponseBody(
                "MFA_REQUIRED",
                "추가 인증이 필요합니다.",
                factorContext,
                nextUiPageUrl,
                2  // Primary 완료, OTT/Passkey 진입 단계
        );
        responseBody.put("nextFactorType", nextFactor.name());
        responseBody.put("nextStepId", factorContext.getCurrentStepId());

        responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
    }

    /**
     * MFA 응답 본문 생성 (progress 정보 포함)
     *
     * @param currentStep 현재 단계 (1: Primary, 2: OTT, 3: Passkey)
     */
    private Map<String, Object> createMfaResponseBody(String status, String message,
                                                      FactorContext factorContext, String nextStepUrl, int currentStep) {
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", status);
        responseBody.put("message", message);
        responseBody.put("mfaSessionId", factorContext.getMfaSessionId());
        responseBody.put("nextStepUrl", nextStepUrl);
        responseBody.put("progress", createProgressInfo(currentStep, 3)); // 총 3단계 (Primary → OTT → Passkey)

        return responseBody;
    }

    /**
     * 개선: Repository 패턴을 통한 무효한 컨텍스트 처리 (HttpSession 직접 접근 제거)
     */
    private void handleInvalidContext(HttpServletResponse response, HttpServletRequest request,
                                      String errorCode, String logMessage,
                                      @Nullable Authentication authentication) throws IOException {
        log.warn("Invalid FactorContext using {} repository: {}. User: {}",
                sessionRepository.getRepositoryType(), logMessage,
                (authentication != null ? ((UserDto)authentication.getPrincipal()).getUsername() : "Unknown"));

        // 개선: Repository를 통한 세션 정리 (HttpSession 직접 접근 제거)
        String oldSessionId = sessionRepository.getSessionId(request);
        if (oldSessionId != null) {
            try {
                stateMachineIntegrator.releaseStateMachine(oldSessionId);
                sessionRepository.removeSession(oldSessionId, request, response);
            } catch (Exception e) {
                log.warn("Failed to cleanup invalid session using {} repository: {}",
                        sessionRepository.getRepositoryType(), oldSessionId, e);
            }
        }

        Map<String, Object> errorResponse = new HashMap<>();

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, errorCode,
                "MFA 세션 컨텍스트 오류: " + logMessage, request.getRequestURI(), errorResponse);
    }

    private String determineChalllengeUrl(FactorContext ctx, HttpServletRequest request) {
        if (ctx.getCurrentProcessingFactor() == null) {
            return request.getContextPath() + authUrlProvider.getMfaSelectFactorUi();
        }

        return switch (ctx.getCurrentProcessingFactor()) {
            case OTT -> request.getContextPath() +
                    authUrlProvider.getOttRequestCodeUi();
            case PASSKEY -> request.getContextPath() +
                    authUrlProvider.getPasskeyChallengeUi();
            default -> request.getContextPath() + authUrlProvider.getMfaSelectFactorUi();
        };
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {
        SavedRequest savedRequest = this.requestCache.getRequest(request, response);
        if (savedRequest != null) {
            this.requestCache.removeRequest(request, response);
            log.debug("Redirecting to saved request URL: {}", savedRequest.getRedirectUrl());
            return savedRequest.getRedirectUrl();
        }
        String defaultTargetUrl = "/home";
        String targetUrl = request.getContextPath() + defaultTargetUrl;
        log.debug("Redirecting to default target URL: {}", targetUrl);
        return targetUrl;
    }

    /**
     * AI에 의해 인증이 차단된 경우 처리
     * 
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param ctx 팩터 컨텍스트
     * @throws IOException I/O 예외
     */
    private void handleAuthenticationBlocked(HttpServletRequest request, 
                                            HttpServletResponse response,
                                            FactorContext ctx) throws IOException {
        String blockReason = (String) ctx.getAttribute("blockReason");
        Double riskScore = (Double) ctx.getAttribute("aiRiskScore");
        
        // 감사 로깅
        log.error("SECURITY_ALERT: Authentication blocked for user '{}' - Risk Score: {}, Reason: {}", 
                ctx.getUsername(), riskScore, blockReason);
        
        // 차단 정보를 응답에 포함
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", "AUTHENTICATION_BLOCKED");
        errorResponse.put("blocked", true);  // SDK에서 차단 상태 감지용
        errorResponse.put("message", "인증이 보안 정책에 의해 차단되었습니다. 관리자에게 문의하세요.");
        errorResponse.put("supportContact", "security@example.com");  // 지원 연락처
        errorResponse.put("username", ctx.getUsername());
        errorResponse.put("timestamp", System.currentTimeMillis());

        // 디버그 모드에서만 상세 정보 포함
        if (log.isDebugEnabled()) {
            errorResponse.put("riskScore", riskScore);
            errorResponse.put("reason", blockReason);
        }
        
        // State Machine 정리
        try {
            stateMachineIntegrator.releaseStateMachine(ctx.getMfaSessionId());
            sessionRepository.removeSession(ctx.getMfaSessionId(), request, response);
        } catch (Exception e) {
            log.warn("Failed to cleanup blocked session: {}", ctx.getMfaSessionId(), e);
        }
        
        // 에러 응답 전송
        responseWriter.writeErrorResponse(
            response,
            HttpServletResponse.SC_FORBIDDEN,
            "AUTHENTICATION_BLOCKED",
            "인증이 보안 정책에 의해 차단되었습니다. 관리자에게 문의하세요.",
            request.getRequestURI(),
            errorResponse
        );
    }
    
    private void handleConfigError(HttpServletResponse response, HttpServletRequest request,
                                   @Nullable FactorContext ctx, String message) throws IOException {
        String flowTypeName = (ctx != null && StringUtils.hasText(ctx.getFlowTypeName())) ?
                ctx.getFlowTypeName() : "Unknown";
        String username = (ctx != null && StringUtils.hasText(ctx.getUsername())) ?
                ctx.getUsername() : "Unknown";
        log.error("Configuration error for flow '{}', user '{}': {}", flowTypeName, username, message);

        String errorCode = "MFA_FLOW_CONFIG_ERROR";
        if (ctx != null) {
            // Map.of() 대신 HashMap 사용
            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("mfaSessionId", ctx.getMfaSessionId());

            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    errorCode, message, request.getRequestURI(), errorDetails);
        } else {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    errorCode, message, request.getRequestURI());
        }
    }

    /**
     * Phase 2: MfaDecision에 따라 다음 이벤트 전송
     */
    private boolean sendNextMfaEvent(MfaDecision decision, String mfaSessionId, HttpServletRequest request) {
        FactorContext context = stateMachineIntegrator.loadFactorContext(mfaSessionId);
        if (context == null) {
            log.error("FactorContext not found for session: {}", mfaSessionId);
            return false;
        }

        // 차단된 경우 - 이미 처리되었으므로 여기서는 스킵
        if (decision.isBlocked()) {
            log.debug("Blocked decision already handled for session: {}", mfaSessionId);
            return true;
        }

        // MFA 불필요
        if (!decision.isRequired()) {
            boolean sent = stateMachineIntegrator.sendEvent(MfaEvent.MFA_NOT_REQUIRED, context, request);
            log.debug("MFA_NOT_REQUIRED event sent for session: {}, accepted: {}", mfaSessionId, sent);
            return sent;
        }

        // MFA 필요 - 자동으로 챌린지 시작
        // 자동 팩터 결정 및 설정
        AuthType autoSelectedFactor = determineAutoFactor(context, decision);
        if (autoSelectedFactor == null) {
            log.error("Failed to determine auto factor for session: {}", mfaSessionId);
            return false;
        }

        // Context에 팩터 설정
        context.setCurrentProcessingFactor(autoSelectedFactor);
        context.setAttribute("autoSelected", true);

        // 다음 stepId 결정 (FlowConfig에서 조회)
        setCurrentStepId(context, autoSelectedFactor);

        // 이벤트 전송 (sendEvent 내부에서 자동으로 persist하므로 중복 저장 제거)
        boolean sent = stateMachineIntegrator.sendEvent(MfaEvent.INITIATE_CHALLENGE_AUTO, context, request);
        log.info("INITIATE_CHALLENGE_AUTO event sent for session: {}, accepted: {}, factor: {}",
                  mfaSessionId, sent, autoSelectedFactor);
        return sent;
    }

    /**
     * 자동 팩터 결정 로직
     *
     * @param context FactorContext
     * @param decision MfaDecision
     * @return 결정된 팩터 (실패 시 null)
     */
    private AuthType determineAutoFactor(FactorContext context, MfaDecision decision) {
        String sessionId = context.getMfaSessionId();

        // 1. MfaDecision의 requiredFactors에서 첫 번째 팩터
        if (decision.getRequiredFactors() != null && !decision.getRequiredFactors().isEmpty()) {
            AuthType firstFactor = decision.getRequiredFactors().getFirst();

            // 사용 가능한 팩터인지 확인
            if (context.getAvailableFactors() != null &&
                context.getAvailableFactors().contains(firstFactor)) {
                log.info("Auto-selected factor from MfaDecision: {} for session: {}",
                         firstFactor, sessionId);
                return firstFactor;
            }
        }

        // 2. AvailableFactors에서 첫 번째 팩터 (폴백)
        Set<AuthType> availableFactors = context.getAvailableFactors();
        if (availableFactors != null && !availableFactors.isEmpty()) {
            AuthType firstAvailable = availableFactors.iterator().next();
            log.info("Auto-selected first available factor: {} for session: {}",
                     firstAvailable, sessionId);
            return firstAvailable;
        }

        log.error("No available factors for auto-selection in session: {}", sessionId);
        return null;
    }

    /**
     * FlowConfig에서 팩터에 해당하는 stepId를 찾아 설정
     *
     * @param context FactorContext
     * @param factorType 팩터 타입
     */
    private void setCurrentStepId(FactorContext context, AuthType factorType) {
        try {
            // PlatformConfig에서 MFA FlowConfig 조회
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);

            AuthenticationFlowConfig flowConfig = platformConfig.getFlows().stream()
                .filter(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()))
                .findFirst()
                .orElse(null);

            if (flowConfig == null) {
                log.warn("MFA FlowConfig not found, stepId will not be set");
                return;
            }

            // 팩터 타입과 일치하는 스텝 찾기
            AuthenticationStepConfig nextStep = flowConfig.getStepConfigs().stream()
                .filter(step -> factorType.name().equalsIgnoreCase(step.getType()))
                .findFirst()
                .orElse(null);

            if (nextStep != null) {
                context.setCurrentStepId(nextStep.getStepId());
                log.debug("Set currentStepId: {} for factor: {} in session: {}",
                         nextStep.getStepId(), factorType, context.getMfaSessionId());
            } else {
                log.warn("No step config found for factor: {} in session: {}",
                        factorType, context.getMfaSessionId());
            }
        } catch (Exception e) {
            log.error("Error setting currentStepId for factor: {} in session: {}",
                     factorType, context.getMfaSessionId(), e);
        }
    }
}