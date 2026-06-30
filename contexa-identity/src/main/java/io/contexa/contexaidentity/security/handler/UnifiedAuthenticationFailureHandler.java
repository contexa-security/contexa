/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustAccessControlFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.ServletException;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.StringUtils;


@Slf4j
public final class UnifiedAuthenticationFailureHandler extends AbstractTokenBasedFailureHandler {

    private static final int MAX_BLOCK_MFA_ATTEMPTS = 2;
    private static final String UNKNOWN_USER = "UnknownUser";

    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;
    private final ZeroTrustActionRepository actionRedisRepository;
    private final MfaSettings mfaSettings;
    private final IBlockedUserRecorder blockedUserRecorder;
    private final CentralAuditFacade centralAuditFacade;
    private final LoginPolicyHandler loginPolicyService;
    private final HCADDataStore hcadDataStore;

    public UnifiedAuthenticationFailureHandler(AuthResponseWriter responseWriter,
                                               MfaStateMachineIntegrator stateMachineIntegrator,
                                               MfaSessionRepository sessionRepository,
                                               ZeroTrustActionRepository actionRedisRepository,
                                               MfaSettings mfaSettings,
                                               IBlockedUserRecorder blockedUserRecorder,
                                               CentralAuditFacade centralAuditFacade,
                                               @Nullable LoginPolicyHandler loginPolicyService,
                                               @Nullable HCADDataStore hcadDataStore) {
        super(responseWriter);
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.sessionRepository = sessionRepository;
        this.actionRedisRepository = actionRedisRepository;
        this.mfaSettings = mfaSettings;
        this.blockedUserRecorder = blockedUserRecorder;
        this.centralAuditFacade = centralAuditFacade;
        this.loginPolicyService = loginPolicyService;
        this.hcadDataStore = hcadDataStore;
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
        String usernameForLog = extractUsernameForLogging(request, factorContext);
        String sessionIdForLog = extractSessionIdForLogging(factorContext);
        recordHcadAuthenticationFailure(request, usernameForLog);

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
                exception, failureDuration, getClientInfo(request), request);
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

        try {
            stateMachineIntegrator.sendEvent(MfaEvent.FACTOR_VERIFICATION_FAILED, factorContext, request);
        } catch (Exception e) {
            log.error("Failed to send FACTOR_VERIFICATION_FAILED event for session: {}",
                    factorContext.getMfaSessionId(), e);
        }

        Boolean blockMfaFlow = (Boolean) factorContext.getAttribute(
                ZeroTrustAccessControlFilter.BLOCK_MFA_FLOW_ATTRIBUTE);
        if (Boolean.TRUE.equals(blockMfaFlow)
                && factorContext.getCurrentState() == MfaState.MFA_RETRY_LIMIT_EXCEEDED) {
            handleBlockMfaFailure(request, response, factorContext);
            return;
        }

        int attempts = factorContext.getRetryCount();
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

        if (loginPolicyService != null && isKnownUsername(usernameForLog)) {
            try {
                loginPolicyService.onLoginFailure(usernameForLog);
            } catch (Exception e) {
                log.error("Failed to record login failure for user: {}", usernameForLog, e);
            }
        }

        if (factorContext != null && StringUtils.hasText(factorContext.getMfaSessionId())) {
            try {
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, factorContext, request);
            } catch (Exception e) {
                log.error("Failed to send SYSTEM_ERROR event during cleanup", e);
            }
            cleanupSessionUsingRepository(request, response, factorContext.getMfaSessionId());
        }

        if (exception instanceof CredentialsExpiredException) {
            String passwordChangeUrl = request.getContextPath() + "/password-change?username="
                    + URLEncoder.encode(usernameForLog, StandardCharsets.UTF_8) + "&expired=true";
            response.sendRedirect(passwordChangeUrl);
            return;
        }

        String errorCode = "PRIMARY_AUTH_FAILED";
        String errorMessage = "Invalid username or password.";
        FailureType failureType = FailureType.PRIMARY_AUTH_FAILED;

        if (exception.getMessage() != null && exception.getMessage().contains("MFA")) {
            errorCode = "MFA_GLOBAL_FAILURE";
            errorMessage = "An error occurred during MFA processing: " + exception.getMessage();
            failureType = FailureType.MFA_GLOBAL_FAILURE;
        }

        String failureRedirectUrl = request.getContextPath() + "/login?error=" + errorCode.toLowerCase();

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
                    "SESSION_NOT_FOUND", "MFA session not found.",
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

    private void handleBlockMfaFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FactorContext factorContext) throws IOException {
        String userId = factorContext.getUsername();
        long failCount = actionRedisRepository.incrementBlockMfaFailCount(userId);

        if (failCount >= MAX_BLOCK_MFA_ATTEMPTS) {
            log.error("[UnifiedAuthFailure] BLOCK MFA max attempts reached, triggering SOAR: userId={}", userId);
            if (blockedUserRecorder != null) {
                blockedUserRecorder.markMfaFailed(userId);
            }
            actionRedisRepository.clearBlockMfaPending(userId);
        } else {
            log.error("[UnifiedAuthFailure] BLOCK MFA failed, attempt {}/{}: userId={}", failCount, MAX_BLOCK_MFA_ATTEMPTS, userId);
        }

        String redirectUrl = request.getContextPath() + "/contexa/zero-trust/blocked";

        Map<String, Object> body = new HashMap<>();
        body.put("blockMfaFailed", true);
        body.put("redirectUrl", redirectUrl);
        body.put("failCount", failCount);
        body.put("maxAttempts", MAX_BLOCK_MFA_ATTEMPTS);

        if (!response.isCommitted()) {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                    "BLOCK_MFA_FAILED", "Block MFA verification failed",
                    request.getRequestURI(), body);
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
        errorDetails.put("maxAttempts", mfaSettings.getMaxRetryAttempts());
        return errorDetails;
    }

    private String extractUsernameForLogging(HttpServletRequest request, FactorContext factorContext) {
        if (factorContext != null && StringUtils.hasText(factorContext.getUsername())) {
            return factorContext.getUsername();
        }
        String submittedUsername = request.getParameter("username");
        if (StringUtils.hasText(submittedUsername)) {
            return submittedUsername.trim();
        }
        String submittedEmail = request.getParameter("email");
        if (StringUtils.hasText(submittedEmail)) {
            return submittedEmail.trim();
        }
        return UNKNOWN_USER;
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

    private void recordHcadAuthenticationFailure(HttpServletRequest request, String username) {
        if (hcadDataStore == null || !isKnownUsername(username)) {
            return;
        }
        try {
            hcadDataStore.recordLoginFailure(username.trim(), null, System.currentTimeMillis());
        } catch (Exception e) {
            log.error("Failed to record HCAD authentication failure counter for user: {}", username, e);
        }
    }

    private boolean isKnownUsername(String username) {
        return StringUtils.hasText(username) && !UNKNOWN_USER.equals(username);
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
                                  Map<String, String> clientInfo, HttpServletRequest request) {

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

        if (centralAuditFacade != null) {
            try {
                Map<String, Object> details = new HashMap<>();
                details.put("factorType", factorTypeStr);
                details.put("exceptionClass", exception.getClass().getSimpleName());
                details.put("durationMs", duration);
                details.put("xForwardedFor", clientInfo.get("xForwardedFor"));

                centralAuditFacade.recordAsync(AuditRecord.builder()
                        .eventCategory(AuditEventCategory.AUTHENTICATION_FAILURE)
                        .principalName(username != null ? username : "UNKNOWN")
                        .eventSource("IDENTITY")
                        .clientIp(clientInfo.get("remoteAddr"))
                        .sessionId(sessionId)
                        .userAgent(clientInfo.get("userAgent"))
                        .resourceIdentifier(username != null ? username : "UNKNOWN")
                        .requestUri(request.getRequestURI())
                        .httpMethod(request.getMethod())
                        .action("AUTHENTICATION")
                        .decision("DENY")
                        .outcome("FAILED")
                        .reason(exception.getMessage())
                        .details(details)
                        .build());
            } catch (Exception e) {
                log.error("Failed to audit authentication failure", e);
            }
        }
    }

}
