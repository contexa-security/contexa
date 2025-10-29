package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.domain.dto.UserDto;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
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

    public PrimaryAuthenticationSuccessHandler(MfaPolicyProvider mfaPolicyProvider, TokenService tokenService, AuthResponseWriter responseWriter, AuthContextProperties authContextProperties, ApplicationContext applicationContext, MfaStateMachineIntegrator stateMachineIntegrator, MfaSessionRepository sessionRepository, AuthUrlProvider authUrlProvider) {
        super(tokenService,responseWriter,sessionRepository,stateMachineIntegrator,authContextProperties);
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.responseWriter = responseWriter;
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.sessionRepository = sessionRepository;
        this.authUrlProvider = authUrlProvider;
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

        mfaPolicyProvider.evaluateMfaRequirementAndDetermineInitialStep(factorContext);
        
        // AI가 인증을 차단한 경우 처리
        if (factorContext.getAttribute("blocked") != null &&
            (Boolean) factorContext.getAttribute("blocked")) {
            
            log.warn("Authentication blocked by AI policy for user: {} - Reason: {}", 
                    factorContext.getUsername(), factorContext.getAttribute("blockReason"));
            
            // 차단 응답 처리
            handleAuthenticationBlocked(request, response, factorContext);
            return;
        }

        FactorContext finalFactorContext = stateMachineIntegrator.loadFactorContext(mfaSessionId);
        if (finalFactorContext == null) { // 매우 예외적인 상황
            handleInvalidContext(response, request, "CONTEXT_LOST", "MFA 처리 중 컨텍스트 유실.", authentication);
            return;
        }

        // 4. 최종 상태에 따른 응답 생성
        MfaState currentState = finalFactorContext.getCurrentState();

        switch (currentState) {
            case MFA_NOT_REQUIRED, MFA_SUCCESSFUL:
                log.info("MFA not required for user: {}. Proceeding with final authentication success.", username);
                handleFinalAuthenticationSuccess(request, response, authentication, factorContext);
                break;

            case AWAITING_FACTOR_SELECTION:
                log.info("MFA required for user: {}. State: AWAITING_FACTOR_SELECTION", username);
                handleFactorSelectionRequired(request, response, factorContext);
                break;

            case FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION:
                log.info("MFA required for user: {}. Proceeding directly to challenge", username);
                handleDirectChallenge(request, response, factorContext);
                break;

            default:
                log.error("Unexpected FactorContext state ({}) for user {} after policy evaluation",
                        currentState, username);
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, factorContext, request);
                handleConfigError(response, request, factorContext, "MFA 처리 중 예상치 못한 상태입니다.");
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
}