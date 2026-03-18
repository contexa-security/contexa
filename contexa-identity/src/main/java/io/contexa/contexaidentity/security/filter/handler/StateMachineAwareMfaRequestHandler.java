package io.contexa.contexaidentity.security.filter.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.filter.matcher.MfaRequestType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.MfaTimeUtils;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Slf4j
public class StateMachineAwareMfaRequestHandler implements MfaRequestHandler {

    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSettings mfaSettings;
    private final AuthUrlProvider authUrlProvider;
    private final MfaSessionRepository sessionRepository;
    private final MfaFlowUrlRegistry mfaFlowUrlRegistry;

    public StateMachineAwareMfaRequestHandler(AuthContextProperties authContextProperties,
                                              AuthResponseWriter responseWriter,
                                              ApplicationContext applicationContext,
                                              MfaStateMachineIntegrator stateMachineIntegrator,
                                              AuthUrlProvider authUrlProvider,
                                              MfaSessionRepository sessionRepository,
                                              MfaFlowUrlRegistry mfaFlowUrlRegistry) {
        this.authContextProperties = authContextProperties;
        this.responseWriter = responseWriter;
        this.applicationContext = applicationContext;
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.mfaSettings = authContextProperties.getMfa();
        this.authUrlProvider = authUrlProvider;
        this.sessionRepository = sessionRepository;
        this.mfaFlowUrlRegistry = mfaFlowUrlRegistry;
    }

    @Override
    public void handleRequest(MfaRequestType requestType, HttpServletRequest request,
                              HttpServletResponse response, FactorContext context,
                              FilterChain filterChain) throws IOException {

        String sessionId = context.getMfaSessionId();
        try {
            processRequestByType(requestType, request, response, context, filterChain);
        } catch (Exception e) {
            log.error("Error in unified State Machine request handling for session: {}", sessionId, e);
            handleProcessingError(request, response, context, e);
        }
    }

    @Override
    public void handleTerminalContext(HttpServletRequest request, HttpServletResponse response,
                                      FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();
        MfaState currentState = context.getCurrentState();

        MfaState latestState = stateMachineIntegrator.getCurrentState(sessionId);
        if (latestState != currentState) {
            log.error("State mismatch detected: context={}, stateMachine={}", currentState, latestState);
            context.changeState(latestState);
            currentState = latestState;
        }

        Map<String, Object> responseBody = createBaseResponse(context);
        responseBody.put("terminal", true);
        responseBody.put("finalState", currentState.name());

        handleTerminalState(currentState, request, response, responseBody);

        // Cleanup both state machine and session repository
        cleanupTerminalSession(sessionId, request, response);
    }

    private void handleTerminalState(MfaState state, HttpServletRequest request,
                                     HttpServletResponse response, Map<String, Object> responseBody) throws IOException {
        String contextPath = request.getContextPath();
        String requestUri = request.getRequestURI();

        switch (state) {
            case MFA_SUCCESSFUL -> {
                responseBody.put("status", "MFA_COMPLETED");
                responseBody.put("message", "MFA authentication completed successfully.");
                responseBody.put("redirectUrl", contextPath + "/");
                responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
            }
            case MFA_NOT_REQUIRED -> {
                responseBody.put("status", "MFA_NOT_REQUIRED");
                responseBody.put("message", "MFA is not required.");
                responseBody.put("redirectUrl", contextPath + "/");
                responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
            }
            case MFA_FAILED_TERMINAL, MFA_RETRY_LIMIT_EXCEEDED -> {
                AuthUrlProvider provider = resolveProvider(request);
                responseBody.put("status", "MFA_FAILED");
                responseBody.put("message", "MFA authentication failed.");
                responseBody.put("redirectUrl", contextPath + provider.getPrimaryLoginPage());
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                        "MFA_FAILED", "MFA authentication failed", requestUri, responseBody);
            }
            case MFA_SESSION_EXPIRED -> {
                AuthUrlProvider provider = resolveProvider(request);
                responseBody.put("status", "SESSION_EXPIRED");
                responseBody.put("message", "MFA session has expired.");
                responseBody.put("redirectUrl", contextPath + provider.getPrimaryLoginPage());
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                        "SESSION_EXPIRED", "Session expired", requestUri, responseBody);
            }
            case MFA_CANCELLED -> {
                AuthUrlProvider provider = resolveProvider(request);
                responseBody.put("status", "MFA_CANCELLED");
                responseBody.put("message", "MFA was cancelled by user.");
                responseBody.put("redirectUrl", contextPath + provider.getPrimaryLoginPage());
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        "MFA_CANCELLED", "MFA cancelled", requestUri, responseBody);
            }
            case MFA_SYSTEM_ERROR -> {
                AuthUrlProvider provider = resolveProvider(request);
                responseBody.put("status", "SYSTEM_ERROR");
                responseBody.put("message", "A system error has occurred.");
                responseBody.put("redirectUrl", contextPath + provider.getPrimaryLoginPage());
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "SYSTEM_ERROR", "System error", requestUri, responseBody);
            }
            default -> {
                responseBody.put("status", "UNKNOWN_TERMINAL_STATE");
                responseBody.put("message", "Unknown terminal state: " + state);
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "UNKNOWN_STATE", "Unknown state", requestUri, responseBody);
            }
        }
    }

    @Override
    public void handleGenericError(HttpServletRequest request, HttpServletResponse response,
                                   FactorContext context, Exception error) throws ServletException, IOException {
        String sessionId = context != null ? context.getMfaSessionId() : "unknown";
        log.error("Generic error in unified State Machine MFA handling for session: {}", sessionId, error);

        if (context != null) {
            try {
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, context, request);
            } catch (Exception e) {
                log.error("Failed to send SYSTEM_ERROR event to State Machine", e);
            }
        }

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "MFA_PROCESSING_ERROR");
        errorResponse.put("message", "A system error occurred during MFA processing.");
        errorResponse.put("timestamp", System.currentTimeMillis());

        if (context != null) {
            errorResponse.put("mfaSessionId", context.getMfaSessionId());
            errorResponse.put("currentState", context.getCurrentState().name());
        }

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "MFA_PROCESSING_ERROR", error.getMessage(), request.getRequestURI(), errorResponse);
    }

    private void processRequestByType(MfaRequestType requestType, HttpServletRequest request,
                                      HttpServletResponse response, FactorContext context,
                                      FilterChain filterChain) throws ServletException, IOException {
        switch (requestType) {
            case FACTOR_SELECTION:
                handleFactorSelection(request, response, context);
                break;

            case CHALLENGE_INITIATION:
                handleChallengeInitiation(request, response, context);
                break;

            case OTT_CODE_REQUEST:

                filterChain.doFilter(request, response);
                break;

            case FACTOR_VERIFICATION:
            case OTT_CODE_VERIFY:
                filterChain.doFilter(request, response);
                break;

            case CANCEL_MFA:
                handleCancelMfa(request, response, context);
                break;

            case LOGIN_PROCESSING:
                filterChain.doFilter(request, response);
                break;

            default:
                Map<String, Object> errorResponse = createErrorResponse(context, "UNSUPPORTED_REQUEST",
                        "Unsupported request type: " + requestType.getDescription());
                errorResponse.put("requestType", requestType.name());
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        "UNSUPPORTED_REQUEST", "Unsupported request type", request.getRequestURI(), errorResponse);
                break;
        }
    }

    private void handleFactorSelection(HttpServletRequest request, HttpServletResponse response,
                                       FactorContext context) throws IOException {
        // GET: return available factors information
        if ("GET".equalsIgnoreCase(request.getMethod())) {
            handleFactorSelectionInfo(request, response, context);
            return;
        }

        // POST: transition to AWAITING_FACTOR_SELECTION if not already there
        if (context.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
            boolean transitioned = stateMachineIntegrator.sendEvent(
                    MfaEvent.MFA_REQUIRED_SELECT_FACTOR, context, request);
            if (!transitioned) {
                handleFactorSelectionFailure(request, response, context);
                return;
            }
        }

        String selectedFactor = extractAndValidateSelectedFactor(request, response, context);
        if (selectedFactor == null) return;

        if (sendFactorSelectionEvent(context, request, selectedFactor)) {
            handleFactorSelectionSuccess(request, response, context, selectedFactor);
        } else {
            handleFactorSelectionFailure(request, response, context);
        }
    }

    private void handleFactorSelectionInfo(HttpServletRequest request, HttpServletResponse response,
                                           FactorContext context) throws IOException {
        Map<String, Object> infoResponse = createSuccessResponse(context, "FACTOR_SELECTION_INFO",
                "Select an authentication factor.");
        Set<AuthType> availableFactors = context.getAvailableFactors();
        if (availableFactors != null) {
            infoResponse.put("availableFactors", availableFactors.stream()
                    .map(AuthType::name).toList());
        }
        responseWriter.writeSuccessResponse(response, infoResponse, HttpServletResponse.SC_OK);
    }

    private void handleChallengeInitiation(HttpServletRequest request, HttpServletResponse response,
                                           FactorContext context) throws IOException {
        MfaSettings mfaSettings = authContextProperties.getMfa();

        if (!isValidStateForChallengeInitiation(context)) {
            handleInvalidStateError(request, response, context, "INVALID_STATE_FOR_CHALLENGE",
                    "Challenge cannot be started in current state: " + context.getCurrentState());
            return;
        }

        if (context.getCurrentProcessingFactor() == null) {
            handleInvalidStateError(request, response, context, "NO_PROCESSING_FACTOR",
                    "No factor selected for processing.");
            return;
        }

        if (hasActiveChallengeForFactor(context)) {

            Object challengeTime = context.getAttribute("challengeInitiatedAt");
            Instant challengeStart = MfaTimeUtils.fromMillis((Long) challengeTime);
            Duration remaining = MfaTimeUtils.getRemainingChallengeTime(challengeStart, mfaSettings);

            Map<String, Object> reuseResponse = createSuccessResponse(context, "CHALLENGE_REUSED",
                    "Reusing existing challenge.");
            reuseResponse.put("challengeUrl", determineNextStepUrl(context, request));
            reuseResponse.put("factorType", context.getCurrentProcessingFactor());
            reuseResponse.put("remainingTimeMs", remaining.toMillis());
            reuseResponse.put("challengeReused", true);

            responseWriter.writeSuccessResponse(response, reuseResponse, HttpServletResponse.SC_OK);
            return;
        }

        boolean accepted = stateMachineIntegrator.sendEvent(MfaEvent.INITIATE_CHALLENGE, context, request);

        if (accepted) {

            Instant challengeStartTime = MfaTimeUtils.nowInstant();
            context.setAttribute("challengeInitiatedAt", MfaTimeUtils.toMillis(challengeStartTime));
            context.setAttribute("ottCodeSent", true);

            Instant challengeExpiryTime = MfaTimeUtils.calculateChallengeExpiry(challengeStartTime, mfaSettings);
            Duration challengeDuration = MfaTimeUtils.getRemainingChallengeTime(challengeStartTime, mfaSettings);

            Map<String, Object> successResponse = createSuccessResponse(context, "CHALLENGE_INITIATED",
                    "Challenge has been initiated.");
            successResponse.put("factorType", context.getCurrentProcessingFactor());
            successResponse.put("challengeUrl", determineNextStepUrl(context, request));
            successResponse.put("challengeInitiatedAt", MfaTimeUtils.toMillis(challengeStartTime));
            successResponse.put("challengeInitiatedAtISO", MfaTimeUtils.toIsoString(challengeStartTime));
            successResponse.put("challengeExpiresAt", MfaTimeUtils.toMillis(challengeExpiryTime));
            successResponse.put("challengeExpiresAtISO", MfaTimeUtils.toIsoString(challengeExpiryTime));
            successResponse.put("challengeTimeoutMs", mfaSettings.getChallengeTimeoutMs());
            successResponse.put("remainingTimeMs", challengeDuration.toMillis());
            successResponse.put("remainingTimeDisplay", MfaTimeUtils.toDisplayString(challengeDuration));

            responseWriter.writeSuccessResponse(response, successResponse, HttpServletResponse.SC_OK);
        } else {
            handleInvalidStateError(request, response, context, "CHALLENGE_INITIATION_FAILED",
                    "Challenge initiation failed.");
        }
    }

    private boolean isValidStateForChallengeInitiation(FactorContext context) {
        MfaState currentState = context.getCurrentState();

        return currentState == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION;
    }

    private boolean hasActiveChallengeForFactor(FactorContext context) {
        AuthType currentFactor = context.getCurrentProcessingFactor();
        if (currentFactor == null) {
            return false;
        }

        if (!currentFactor.isAllowChallengeReuse()) {
            return false;
        }

        Object challengeTime = context.getAttribute("challengeInitiatedAt");
        if (!(challengeTime instanceof Long)) {
            return false;
        }

        return !mfaSettings.isChallengeExpired((Long) challengeTime);
    }

    private void handleCancelMfa(HttpServletRequest request, HttpServletResponse response,
                                 FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();

        boolean accepted = stateMachineIntegrator.sendEvent(MfaEvent.USER_ABORTED_MFA, context, request);

        if (accepted) {
            Map<String, Object> cancelResponse = createSuccessResponse(context, "MFA_CANCELLED",
                    "MFA was cancelled by user.");
            cancelResponse.put("cancelledAt", System.currentTimeMillis());
            cancelResponse.put("redirectUrl", request.getContextPath() + resolveProvider(request).getPrimaryLoginPage());

            responseWriter.writeSuccessResponse(response, cancelResponse, HttpServletResponse.SC_OK);

            scheduleStateMachineCleanup(sessionId);
        } else {
            handleInvalidStateError(request, response, context, "CANCELLATION_FAILED",
                    "MFA cancellation failed.");
        }
    }

    private String extractAndValidateSelectedFactor(HttpServletRequest request, HttpServletResponse response,
                                                    FactorContext context) throws IOException {
        // 1) Form parameter: "factor" or "factorType"
        String selectedFactor = request.getParameter("factor");
        if (selectedFactor == null || selectedFactor.trim().isEmpty()) {
            selectedFactor = request.getParameter("factorType");
        }

        // 2) JSON body: { "factorType": "..." } or { "factor": "..." }
        if ((selectedFactor == null || selectedFactor.trim().isEmpty())
                && request.getContentType() != null
                && request.getContentType().contains("application/json")) {
            try {
                String body = new String(request.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                com.fasterxml.jackson.databind.JsonNode json = new com.fasterxml.jackson.databind.ObjectMapper().readTree(body);
                if (json.has("factorType")) {
                    selectedFactor = json.get("factorType").asText();
                } else if (json.has("factor")) {
                    selectedFactor = json.get("factor").asText();
                }
            } catch (Exception e) {
                log.error("Failed to parse JSON body for factor selection", e);
            }
        }

        if (selectedFactor == null || selectedFactor.trim().isEmpty()) {
            Map<String, Object> errorResponse = createErrorResponse(context, "MISSING_FACTOR_PARAMETER",
                    "Please specify a factor to select.");
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "MISSING_PARAMETER", "Missing factor parameter", request.getRequestURI(), errorResponse);
            return null;
        }
        return selectedFactor.trim();
    }

    private boolean sendFactorSelectionEvent(FactorContext context, HttpServletRequest request, String selectedFactor) {
        try {

            context.setAttribute("selectedFactor", selectedFactor);
            request.setAttribute("selectedFactor", selectedFactor);

            String ottDeliveryMethod = request.getParameter("ottDeliveryMethod");
            if (ottDeliveryMethod != null) {
                context.setAttribute("ottDeliveryMethod", ottDeliveryMethod);
                request.setAttribute("ottDeliveryMethod", ottDeliveryMethod);
            }

            String passkeyType = request.getParameter("passkeyType");
            if (passkeyType != null) {
                context.setAttribute("passkeyType", passkeyType);
                request.setAttribute("passkeyType", passkeyType);
            }

            boolean accepted = stateMachineIntegrator.sendEvent(MfaEvent.FACTOR_SELECTED, context, request);
            if (accepted) {
                // Transition from AWAITING_FACTOR_CHALLENGE_INITIATION to FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION
                stateMachineIntegrator.sendEvent(MfaEvent.INITIATE_CHALLENGE, context, request);
            }
            return accepted;
        } catch (Exception e) {
            log.error("Failed to send factor selection event", e);
            return false;
        }
    }

    private void handleFactorSelectionSuccess(HttpServletRequest request, HttpServletResponse response,
                                              FactorContext context, String selectedFactor) throws IOException {
        Map<String, Object> successResponse = createSuccessResponse(context, "FACTOR_SELECTED",
                "Factor selected successfully.");
        successResponse.put("selectedFactor", selectedFactor);
        successResponse.put("nextStepUrl", determineNextStepUrl(context, request));
        successResponse.put("factorSelectedAt", System.currentTimeMillis());

        responseWriter.writeSuccessResponse(response, successResponse, HttpServletResponse.SC_OK);
    }

    private void handleFactorSelectionFailure(HttpServletRequest request, HttpServletResponse response,
                                              FactorContext context) throws IOException {
        handleInvalidStateError(request, response, context, "FACTOR_SELECTION_REJECTED",
                "Factor selection was rejected.");
    }

    private void handleInvalidStateError(HttpServletRequest request, HttpServletResponse response,
                                         FactorContext context, String errorCode, String message) throws IOException {
        Map<String, Object> errorResponse = createErrorResponse(context, errorCode, message);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                errorCode, message, request.getRequestURI(), errorResponse);
    }

    private void handleProcessingError(HttpServletRequest request, HttpServletResponse response,
                                       FactorContext context, Exception error) throws IOException {
        Map<String, Object> errorResponse = createErrorResponse(context, "REQUEST_PROCESSING_ERROR",
                "An error occurred while processing the request.");
        errorResponse.put("errorType", error.getClass().getSimpleName());
        errorResponse.put("errorMessage", error.getMessage());

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "REQUEST_PROCESSING_ERROR", error.getMessage(), request.getRequestURI(), errorResponse);
    }

    private Map<String, Object> createBaseResponse(FactorContext context) {
        Map<String, Object> response = new HashMap<>();
        response.put("mfaSessionId", context.getMfaSessionId());
        response.put("currentState", context.getCurrentState().name());
        response.put("timestamp", System.currentTimeMillis());
        return response;
    }

    private Map<String, Object> createSuccessResponse(FactorContext context, String status, String message) {
        Map<String, Object> response = createBaseResponse(context);
        response.put("status", status);
        response.put("message", message);
        response.put("success", true);
        return response;
    }

    private Map<String, Object> createErrorResponse(FactorContext context, String error, String message) {
        Map<String, Object> response = createBaseResponse(context);
        response.put("error", error);
        response.put("message", message);
        response.put("success", false);
        return response;
    }

    private String determineNextStepUrl(FactorContext context, HttpServletRequest request) {
        AuthUrlProvider provider = resolveProvider(request);
        if (context.getCurrentProcessingFactor() == null) {
            return request.getContextPath() + provider.getMfaSelectFactor();
        }

        return switch (context.getCurrentProcessingFactor()) {
            case MFA_OTT -> request.getContextPath() +
                    provider.getOttRequestCodeUi();
            case MFA_PASSKEY -> request.getContextPath() +
                    provider.getPasskeyChallengeUi();
            default -> request.getContextPath() + provider.getMfaSelectFactor();
        };
    }

    private AuthUrlProvider resolveProvider(HttpServletRequest request) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
        if (ctx != null && ctx.getFlowTypeName() != null) {
            AuthUrlProvider flowProvider = mfaFlowUrlRegistry.getProvider(ctx.getFlowTypeName());
            if (flowProvider != null) {
                return flowProvider;
            }
        }
        return authUrlProvider;
    }

    private void cleanupTerminalSession(String sessionId, HttpServletRequest request,
                                       HttpServletResponse response) {
        try {
            stateMachineIntegrator.releaseStateMachine(sessionId);
            sessionRepository.removeSession(sessionId, request, response);
        } catch (Exception e) {
            log.error("Failed to cleanup terminal session: {}", sessionId, e);
        }
    }

    private void scheduleStateMachineCleanup(String sessionId) {

        applicationContext.getBean("taskExecutor", java.util.concurrent.Executor.class)
                .execute(() -> {
                    try {
                        Thread.sleep(5000);
                        stateMachineIntegrator.releaseStateMachine(sessionId);
                    } catch (Exception e) {
                        log.error("Error during State Machine cleanup for session: {}", sessionId, e);
                    }
                });
    }
}