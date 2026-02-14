package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.security.identification.UserIdentificationService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public final class UnifiedAuthenticationFailureHandler extends AbstractTokenBasedFailureHandler {

    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;
    private final UserIdentificationService userIdentificationService;

    @Autowired(required = false)
    private ZeroTrustEventPublisher zeroTrustEventPublisher;

    public UnifiedAuthenticationFailureHandler(AuthResponseWriter responseWriter,
                                               MfaStateMachineIntegrator stateMachineIntegrator,
                                               MfaSessionRepository sessionRepository,
                                               UserIdentificationService userIdentificationService) {
        super(responseWriter);
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.sessionRepository = sessionRepository;
        this.userIdentificationService = userIdentificationService;
    }

    @Override
    public final void onAuthenticationFailure(HttpServletRequest request,
                                              HttpServletResponse response,
                                              AuthenticationException exception) throws IOException, ServletException {

        if (response.isCommitted()) {
            log.error("Response already committed on authentication failure");
            return;
        }

        long failureStartTime = System.currentTimeMillis();

        FactorContext factorContext = stateMachineIntegrator.loadFactorContextFromRequest(request);
        String usernameForLog = extractUsernameForLogging(factorContext, exception);
        String sessionIdForLog = extractSessionIdForLogging(factorContext);

        AuthType currentProcessingFactor = (factorContext != null) ? factorContext.getCurrentProcessingFactor() : null;

        if (isMfaFactorFailure(factorContext, currentProcessingFactor)) {
            handleMfaFactorFailure(request, response, exception, factorContext,
                    currentProcessingFactor, usernameForLog, sessionIdForLog);
        } else {
            handlePrimaryAuthOrGlobalMfaFailure(request, response, exception, factorContext,
                    usernameForLog, sessionIdForLog);
        }

        long failureDuration = System.currentTimeMillis() - failureStartTime;
        logSecurityAudit(usernameForLog, sessionIdForLog, currentProcessingFactor,
                exception, failureDuration, getClientInfo(request));
    }

    private void handleMfaFactorFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception, FactorContext factorContext,
                                        AuthType currentProcessingFactor, String usernameForLog,
                                        String sessionIdForLog) throws IOException {

        log.error("MFA Factor Failure using {} repository: Factor '{}' for user '{}' (session ID: '{}') failed. Reason: {}",
                sessionRepository.getRepositoryType(), currentProcessingFactor, usernameForLog, sessionIdForLog, exception.getMessage());

        if (!sessionRepository.existsSession(factorContext.getMfaSessionId())) {
            log.error("MFA session {} not found in {} repository during factor failure processing",
                    factorContext.getMfaSessionId(), sessionRepository.getRepositoryType());
            handleSessionNotFound(request, response, factorContext, exception);
            return;
        }

        factorContext.recordAttempt(currentProcessingFactor, false, "Verification failed: " + exception.getMessage());
        factorContext.incrementAttemptCount(currentProcessingFactor);
        factorContext.setAttribute("retryCount_" + currentProcessingFactor.name(),
                factorContext.getAttemptCount(currentProcessingFactor));

        publishAuthenticationFailureEvent(request, exception, factorContext);

        // Send state machine transition event for factor verification failure
        try {
            stateMachineIntegrator.sendEvent(MfaEvent.FACTOR_VERIFICATION_FAILED, factorContext, request);
        } catch (Exception e) {
            log.error("Failed to send FACTOR_VERIFICATION_FAILED event for session: {}",
                    factorContext.getMfaSessionId(), e);
        }

        int attempts = factorContext.getAttemptCount(currentProcessingFactor);
        Map<String, Object> errorDetails = buildMfaFailureErrorDetails(factorContext, currentProcessingFactor, attempts);

        executeDelegateHandler(request, response, exception, factorContext, FailureType.MFA_FACTOR_FAILED, errorDetails);

        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "MFA_FACTOR_VERIFICATION_FAILED", "MFA factor verification failed",
                    request.getRequestURI(), errorDetails);
        }
    }

    private void handlePrimaryAuthOrGlobalMfaFailure(HttpServletRequest request, HttpServletResponse response,
                                                     AuthenticationException exception, FactorContext factorContext,
                                                     String usernameForLog, String sessionIdForLog)
            throws IOException, ServletException {

        log.error("Primary Authentication or Global MFA Failure using {} repository for user '{}' (MFA Session ID: '{}'). Reason: {}",
                sessionRepository.getRepositoryType(), usernameForLog, sessionIdForLog, exception.getMessage());

        if (factorContext != null && StringUtils.hasText(factorContext.getMfaSessionId())) {
            try {
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, factorContext, request);
            } catch (Exception e) {
                log.error("Failed to send SYSTEM_ERROR event during cleanup", e);
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

        executeDelegateHandler(request, response, exception, factorContext, failureType, errorDetails);

        if (!response.isCommitted()) {
            onPrimaryAuthFailure(request, response, exception, errorDetails);
        }

        if (!response.isCommitted()) {
            if (isApiRequest(request)) {
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                        errorCode, errorMessage, request.getRequestURI(), errorDetails);
            } else {
                response.sendRedirect(failureRedirectUrl);
            }
        }
    }

    private void handleSessionNotFound(HttpServletRequest request, HttpServletResponse response,
                                       FactorContext factorContext, AuthenticationException exception)
            throws IOException {
        log.error("Session not found in {} repository during failure processing: {}",
                sessionRepository.getRepositoryType(), factorContext.getMfaSessionId());

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("mfaSessionId", factorContext.getMfaSessionId());

        executeDelegateHandler(request, response, exception, factorContext,
                FailureType.MFA_SESSION_NOT_FOUND, errorDetails);

        if (!response.isCommitted()) {
            onMfaSessionNotFound(request, response, exception, factorContext, errorDetails);
        }

        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "SESSION_NOT_FOUND", "MFA 세션을 찾을 수 없습니다.",
                    request.getRequestURI(), errorDetails);
        }
    }

    private void onPrimaryAuthFailure(HttpServletRequest request, HttpServletResponse response,
                                      AuthenticationException exception, Map<String, Object> errorDetails)
            throws IOException {

    }

    private void onMfaSessionNotFound(HttpServletRequest request, HttpServletResponse response,
                                      AuthenticationException exception, FactorContext factorContext,
                                      Map<String, Object> errorDetails)
            throws IOException {

    }

    private void cleanupSessionUsingRepository(HttpServletRequest request, HttpServletResponse response,
                                               String mfaSessionId) {
        try {
            stateMachineIntegrator.releaseStateMachine(mfaSessionId);
            sessionRepository.removeSession(mfaSessionId, request, response);
        } catch (Exception e) {
            log.error("Failed to cleanup session using {} repository: {}",
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

        log.error("SECURITY_AUDIT - Authentication Failure: " +
                        "User=[{}], Session=[{}], Factor=[{}], " +
                        "Reason=[{}], Duration=[{}ms], " +
                        "ClientIP=[{}], UserAgent=[{}], XFF=[{}]",
                username, sessionId, factorTypeStr,
                exception.getMessage(), duration,
                clientInfo.get("remoteAddr"),
                clientInfo.get("userAgent"),
                clientInfo.get("xForwardedFor"));
    }

    private void publishAuthenticationFailureEvent(HttpServletRequest request,
                                                   AuthenticationException exception,
                                                   @Nullable FactorContext factorContext) {
        try {
            if (zeroTrustEventPublisher == null) {
                return;
            }

            String username = userIdentificationService.extractUserId(request, null, exception);
            Integer failureCount = extractFailureCount(factorContext);

            Map<String, Object> payload = new HashMap<>();
            payload.put("requestPath", request.getRequestURI());
            payload.put("httpMethod", request.getMethod());
            payload.put("failureReason", exception.getMessage());
            payload.put("exceptionClass", exception.getClass().getName());
            payload.put("failureCount", failureCount);
            payload.put("riskScore", calculateFailureRiskScore(failureCount, exception));

            if (factorContext != null) {
                payload.put("authenticationType", factorContext.getCurrentProcessingFactor() != null ?
                        factorContext.getCurrentProcessingFactor().toString() : "PRIMARY");
                payload.put("deviceId", factorContext.getAttribute(FactorContextAttributes.DeviceAndSession.DEVICE_ID));
            } else {
                payload.put("authenticationType", "PRIMARY");
            }

            zeroTrustEventPublisher.publishAuthenticationFailure(
                    username,
                    request.getSession(false) != null ? request.getSession().getId() : null,
                    extractClientIp(request),
                    request.getHeader("User-Agent"),
                    payload
            );

        } catch (Exception e) {
            log.error("Failed to publish authentication failure event", e);
        }
    }

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

    private Double calculateFailureRiskScore(Integer failureCount, AuthenticationException exception) {
        double score = 0.3;

        if (failureCount != null) {
            if (failureCount > 10) {
                score = 0.9;
            } else if (failureCount > 5) {
                score = 0.7;
            } else if (failureCount > 3) {
                score = 0.5;
            }
        }

        String exceptionName = exception.getClass().getSimpleName();
        if (exceptionName.contains("Locked") || exceptionName.contains("Disabled")) {
            score = Math.min(1.0, score + 0.2);
        }

        return score;
    }
}