package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacore.autonomous.event.domain.AuthenticationFailureEvent;
import io.contexa.contexacore.autonomous.security.identification.UserIdentificationService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 통합 인증 실패 처리 핸들러
 *
 * 개선사항:
 * - PlatformAuthenticationFailureHandler 지원 추가
 * - 하위 클래스 확장점 제공
 * - response.isCommitted() 체크로 중복 응답 방지
 */
@Slf4j
public final class UnifiedAuthenticationFailureHandler extends AbstractTokenBasedFailureHandler implements ApplicationEventPublisherAware  {

    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final MfaSessionRepository sessionRepository;
    private final UserIdentificationService userIdentificationService;
    private final AuthUrlProvider authUrlProvider;

    private ApplicationEventPublisher eventPublisher;

    public UnifiedAuthenticationFailureHandler(AuthResponseWriter responseWriter,
                                               MfaStateMachineIntegrator stateMachineIntegrator,
                                               MfaPolicyProvider mfaPolicyProvider,
                                               MfaSessionRepository sessionRepository,
                                               UserIdentificationService userIdentificationService,
                                               AuthUrlProvider authUrlProvider) {
        super(responseWriter);
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.sessionRepository = sessionRepository;
        this.userIdentificationService = userIdentificationService;
        this.authUrlProvider = authUrlProvider;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.eventPublisher = applicationEventPublisher;
    }

    @Override
    public final void onAuthenticationFailure(HttpServletRequest request,
                                              HttpServletResponse response,
                                              AuthenticationException exception) throws IOException, ServletException {

        if (response.isCommitted()) {
            log.warn("Response already committed on authentication failure");
            return;
        }

        long failureStartTime = System.currentTimeMillis();

        FactorContext factorContext = stateMachineIntegrator.loadFactorContextFromRequest(request);
        String usernameForLog = extractUsernameForLogging(factorContext, exception);
        String sessionIdForLog = extractSessionIdForLogging(factorContext);

        log.debug("Processing authentication failure using {} repository for user: {} session: {}",
                sessionRepository.getRepositoryType(), usernameForLog, sessionIdForLog);

        AuthType currentProcessingFactor = (factorContext != null) ? factorContext.getCurrentProcessingFactor() : null;

        if (isMfaFactorFailure(factorContext, currentProcessingFactor)) {
            handleMfaFactorFailure(request, response, exception, factorContext,
                    currentProcessingFactor, usernameForLog, sessionIdForLog);
        } else {
            handlePrimaryAuthOrGlobalMfaFailure(request, response, exception, factorContext,
                    usernameForLog, sessionIdForLog);
        }

        // 보안 감사 로그
        long failureDuration = System.currentTimeMillis() - failureStartTime;
        logSecurityAudit(usernameForLog, sessionIdForLog, currentProcessingFactor,
                exception, failureDuration, getClientInfo(request));
    }

    /**
     * MFA 팩터 검증 실패 처리
     */
    private void handleMfaFactorFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception, FactorContext factorContext,
                                        AuthType currentProcessingFactor, String usernameForLog,
                                        String sessionIdForLog) throws IOException {

        log.warn("MFA Factor Failure using {} repository: Factor '{}' for user '{}' (session ID: '{}') failed. Reason: {}",
                sessionRepository.getRepositoryType(), currentProcessingFactor, usernameForLog, sessionIdForLog, exception.getMessage());

        if (!sessionRepository.existsSession(factorContext.getMfaSessionId())) {
            log.warn("MFA session {} not found in {} repository during factor failure processing",
                    factorContext.getMfaSessionId(), sessionRepository.getRepositoryType());
            handleSessionNotFound(request, response, factorContext, exception);
            return;
        }

        factorContext.recordAttempt(currentProcessingFactor, false, "Verification failed: " + exception.getMessage());

        publishAuthenticationFailureEvent(request, exception, factorContext);

    }

    /**
     * 1차 인증 실패 또는 전역 MFA 실패 처리
     */
    private void handlePrimaryAuthOrGlobalMfaFailure(HttpServletRequest request, HttpServletResponse response,
                                                     AuthenticationException exception, FactorContext factorContext,
                                                     String usernameForLog, String sessionIdForLog)
            throws IOException, ServletException {

        log.warn("Primary Authentication or Global MFA Failure using {} repository for user '{}' (MFA Session ID: '{}'). Reason: {}",
                sessionRepository.getRepositoryType(), usernameForLog, sessionIdForLog, exception.getMessage());

        if (factorContext != null && StringUtils.hasText(factorContext.getMfaSessionId())) {
            try {
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, factorContext, request);
            } catch (Exception e) {
                log.warn("Failed to send SYSTEM_ERROR event during cleanup", e);
            }
            cleanupSessionUsingRepository(request, response, factorContext.getMfaSessionId());
        }

        String errorCode = "PRIMARY_AUTH_FAILED";
        String errorMessage = "아이디 또는 비밀번호가 잘못되었습니다.";
        FailureType failureType = FailureType.PRIMARY_AUTH_FAILED;

        if (exception.getMessage() != null && exception.getMessage().contains("MFA")) {
            errorCode = "MFA_GLOBAL_FAILURE";
            errorMessage = "MFA 처리 중 문제가 발생했습니다: " + exception.getMessage();
            failureType = FailureType.MFA_GLOBAL_FAILURE;
        }

        String failureRedirectUrl = request.getContextPath() + "/loginForm?error=" + errorCode.toLowerCase();

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("message", errorMessage);
        errorDetails.put("nextStepUrl", failureRedirectUrl);

        // 위임 핸들러 호출 (부모 클래스 공통 메서드 사용)
        executeDelegateHandler(request, response, exception, factorContext, failureType, errorDetails);

        // 하위 클래스 훅 호출
        if (!response.isCommitted()) {
            onPrimaryAuthFailure(request, response, exception, errorDetails);
        }

        // 플랫폼 기본 응답
        if (!response.isCommitted()) {
            if (isApiRequest(request)) {
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                        errorCode, errorMessage, request.getRequestURI(), errorDetails);
            } else {
                response.sendRedirect(failureRedirectUrl);
            }
        }
    }

    /**
     * 세션 미발견 처리
     */
    private void handleSessionNotFound(HttpServletRequest request, HttpServletResponse response,
                                       FactorContext factorContext, AuthenticationException exception)
            throws IOException {
        log.warn("Session not found in {} repository during failure processing: {}",
                sessionRepository.getRepositoryType(), factorContext.getMfaSessionId());

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("mfaSessionId", factorContext.getMfaSessionId());

        // 위임 핸들러 호출 (부모 클래스 공통 메서드 사용)
        executeDelegateHandler(request, response, exception, factorContext,
                FailureType.MFA_SESSION_NOT_FOUND, errorDetails);

        // 하위 클래스 훅 호출
        if (!response.isCommitted()) {
            onMfaSessionNotFound(request, response, exception, factorContext, errorDetails);
        }

        // 플랫폼 기본 응답
        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "SESSION_NOT_FOUND", "MFA 세션을 찾을 수 없습니다.",
                    request.getRequestURI(), errorDetails);
        }
    }

    // ========== 하위 클래스 확장점 ==========

    /**
     * MFA 최대 시도 횟수 초과 시 확장점
     */
    protected void onMfaMaxAttemptsExceeded(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException exception, FactorContext factorContext,
                                            AuthType factor, Map<String, Object> errorDetails)
            throws IOException {
        // 하위 클래스에서 필요시 오버라이드
    }

    /**
     * MFA 팩터 실패 시 확장점
     */
    protected void onMfaFactorFailure(HttpServletRequest request, HttpServletResponse response,
                                      AuthenticationException exception, FactorContext factorContext,
                                      AuthType factor, Map<String, Object> errorDetails)
            throws IOException {
        // 하위 클래스에서 필요시 오버라이드
    }

    /**
     * 1차 인증 실패 시 확장점
     */
    protected void onPrimaryAuthFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception, Map<String, Object> errorDetails)
            throws IOException {
        // 하위 클래스에서 필요시 오버라이드
    }

    /**
     * MFA 세션 미발견 시 확장점
     */
    protected void onMfaSessionNotFound(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception, FactorContext factorContext,
                                        Map<String, Object> errorDetails)
            throws IOException {
        // 하위 클래스에서 필요시 오버라이드
    }

    // ========== 기존 private 메서드들 (변경 없음) ==========

    private void cleanupSessionUsingRepository(HttpServletRequest request, HttpServletResponse response,
                                               String mfaSessionId) {
        try {
            stateMachineIntegrator.releaseStateMachine(mfaSessionId);
            sessionRepository.removeSession(mfaSessionId, request, response);
            log.debug("Session cleanup completed using {} repository for MFA session: {}",
                    sessionRepository.getRepositoryType(), mfaSessionId);
        } catch (Exception e) {
            log.warn("Failed to cleanup session using {} repository: {}",
                    sessionRepository.getRepositoryType(), mfaSessionId, e);
        }
    }

    private Map<String, Object> buildMfaFailureErrorDetails(FactorContext factorContext,
                                                            AuthType currentProcessingFactor,
                                                            int attempts) {
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("mfaSessionId", factorContext.getMfaSessionId());
        errorDetails.put("failedFactor", currentProcessingFactor.name().toUpperCase());
        errorDetails.put("attemptsMade", attempts);
        errorDetails.put("currentState", factorContext.getCurrentState().name());
        errorDetails.put("timestamp", System.currentTimeMillis());
        return errorDetails;
    }

    private String extractUsernameForLogging(FactorContext factorContext, AuthenticationException exception) {
        if (factorContext != null && StringUtils.hasText(factorContext.getUsername())) {
            return factorContext.getUsername();
        }
        return "UnknownUser";
    }

    private String extractSessionIdForLogging(FactorContext factorContext) {
        if (factorContext != null && StringUtils.hasText(factorContext.getMfaSessionId())) {
            return factorContext.getMfaSessionId();
        }
        return "NoMfaSession";
    }

    private boolean isApiRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        if (acceptHeader != null && acceptHeader.contains("application/json")) {
            return true;
        }

        String contentType = request.getContentType();
        if (contentType != null && contentType.contains("application/json")) {
            return true;
        }

        String requestURI = request.getRequestURI();
        return requestURI != null && (requestURI.startsWith("/api/") || requestURI.contains("/api/"));
    }

    private boolean isMfaFactorFailure(FactorContext factorContext, AuthType currentProcessingFactor) {
        if (factorContext == null || currentProcessingFactor == null) {
            return false;
        }

        MfaState currentState = factorContext.getCurrentState();
        return currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                currentState == MfaState.FACTOR_VERIFICATION_PENDING;
    }

    private Map<String, String> getClientInfo(HttpServletRequest request) {
        Map<String, String> clientInfo = new HashMap<>();
        clientInfo.put("userAgent", request.getHeader("User-Agent"));
        clientInfo.put("remoteAddr", request.getRemoteAddr());
        clientInfo.put("xForwardedFor", request.getHeader("X-Forwarded-For"));
        clientInfo.put("referer", request.getHeader("Referer"));
        return clientInfo;
    }

    private void logSecurityAudit(String username, String sessionId, AuthType factorType,
                                  AuthenticationException exception, long duration,
                                  Map<String, String> clientInfo) {

        String factorTypeStr = (factorType != null) ? factorType.name() : "PRIMARY_AUTH";

        log.warn("SECURITY_AUDIT - Authentication Failure: " +
                        "User=[{}], Session=[{}], Factor=[{}], " +
                        "Reason=[{}], Duration=[{}ms], " +
                        "ClientIP=[{}], UserAgent=[{}], XFF=[{}]",
                username, sessionId, factorTypeStr,
                exception.getMessage(), duration,
                clientInfo.get("remoteAddr"),
                clientInfo.get("userAgent"),
                clientInfo.get("xForwardedFor"));
    }
    
    /**
     * 인증 실패 이벤트 발행
     * 
     * 실패한 인증 시도를 추적하여 공격 패턴을 분석합니다.
     */
    private void publishAuthenticationFailureEvent(HttpServletRequest request,
                                                   AuthenticationException exception,
                                                   @Nullable FactorContext factorContext) {
        try {
            if (eventPublisher == null) {
                log.debug("ApplicationEventPublisher not available, skipping failure event publication");
                return;
            }
            
            // 실패 정보 추출
            String username = userIdentificationService.extractUserId(request, null, exception);
            Integer failureCount = extractFailureCount(factorContext);
            
            // 이벤트 빌더 생성
            AuthenticationFailureEvent.AuthenticationFailureEventBuilder builder = 
                AuthenticationFailureEvent.builder()
                    .eventId(java.util.UUID.randomUUID().toString())
                    .userId(username)
                    .username(username)
                    .sessionId(request.getSession(false) != null ? request.getSession().getId() : null)
                    .eventTimestamp(java.time.LocalDateTime.now())
                    .sourceIp(extractClientIp(request))
                    .userAgent(request.getHeader("User-Agent"))
                    .failureReason(exception.getMessage())
                    .exceptionClass(exception.getClass().getName())
                    .exceptionMessage(exception.getMessage())
                    .failureCount(failureCount);
            
            // FactorContext 에서 추가 정보 추출
            if (factorContext != null) {
                builder.authenticationType(factorContext.getCurrentProcessingFactor() != null ?
                                          factorContext.getCurrentProcessingFactor().toString() : "PRIMARY")
                       .deviceId((String) factorContext.getAttribute(FactorContextAttributes.DeviceAndSession.DEVICE_ID));
                
                // 공격 패턴 감지
                boolean bruteForce = failureCount > 10;
                builder.bruteForceDetected(bruteForce);
                
                // 위험 점수
                Double riskScore = calculateFailureRiskScore(failureCount, exception);
                builder.riskScore(riskScore);
            } else {
                builder.authenticationType("PRIMARY");
            }
            
            // 메타데이터
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("requestPath", request.getRequestURI());
            metadata.put("httpMethod", request.getMethod());
            builder.metadata(metadata);
            
            // 이벤트 발행
            AuthenticationFailureEvent event = builder.build();
            eventPublisher.publishEvent(event);
            
            log.debug("Published authentication failure event for user: {}, eventId: {}", 
                     username, event.getEventId());
            
        } catch (Exception e) {
            log.error("Failed to publish authentication failure event", e);
        }
    }

    /**
     * 실패 횟수 추출
     */
    private Integer extractFailureCount(FactorContext factorContext) {
        if (factorContext == null) {
            return 1;
        }

        Object failCount = factorContext.getAttribute(FactorContextAttributes.StateControl.FAILURE_COUNT);
        if (failCount instanceof Integer) {
            return (Integer) failCount;
        }

        return 1;
    }
    
    /**
     * 실패 위험 점수 계산
     */
    private Double calculateFailureRiskScore(Integer failureCount, AuthenticationException exception) {
        double score = 0.3;  // 기본 점수
        
        if (failureCount != null) {
            if (failureCount > 10) {
                score = 0.9;  // 매우 높음
            } else if (failureCount > 5) {
                score = 0.7;  // 높음
            } else if (failureCount > 3) {
                score = 0.5;  // 중간
            }
        }
        
        // 특정 예외 타입에 따른 조정
        String exceptionName = exception.getClass().getSimpleName();
        if (exceptionName.contains("Locked") || exceptionName.contains("Disabled")) {
            score = Math.min(1.0, score + 0.2);
        }
        
        return score;
    }
    
    /**
     * Phase 2.2: errorEventRecommendation 처리 메서드
     *
     * Action에서 예외 발생 시 설정한 errorEventRecommendation을 읽어서
     * State Machine에 이벤트를 전송합니다.
     *
     * @param factorContext FactorContext
     * @param request HttpServletRequest
     * @param sessionId 세션 ID (로깅용)
     * @return errorEventRecommendation이 처리되었으면 true, 없거나 실패하면 false
     */
    private boolean processErrorEventRecommendation(FactorContext factorContext,
                                                    HttpServletRequest request,
                                                    String sessionId) {
        if (factorContext == null) {
            return false;
        }

        MfaEvent errorEvent = (MfaEvent) factorContext.getAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION);

        if (errorEvent != null) {
            log.debug("Processing error event recommendation: {} for session: {}",
                     errorEvent, sessionId);

            try {
                boolean errorEventSent = stateMachineIntegrator.sendEvent(errorEvent, factorContext, request);

                if (errorEventSent) {
                    // Clear the recommendation after successful processing
                    factorContext.removeAttribute("errorEventRecommendation");
                    log.debug("Error event {} processed successfully for session: {}",
                             errorEvent, sessionId);
                    return true;
                } else {
                    log.error("Failed to send error event {} for session: {}", errorEvent, sessionId);
                }
            } catch (Exception sendError) {
                log.error("Failed to process error event recommendation for session: {}",
                         sessionId, sendError);
            }
        }

        return false;
    }

    // extractClientIp 메서드는 부모 클래스(AbstractTokenBasedFailureHandler)에서 상속받아 사용
}