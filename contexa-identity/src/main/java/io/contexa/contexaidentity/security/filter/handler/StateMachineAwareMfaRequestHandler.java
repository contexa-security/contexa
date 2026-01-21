package io.contexa.contexaidentity.security.filter.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.filter.matcher.MfaRequestType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.MfaTimeUtils;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
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

@Slf4j
public class StateMachineAwareMfaRequestHandler implements MfaRequestHandler {

    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSettings mfaSettings;
    private final AuthUrlProvider authUrlProvider;

    public StateMachineAwareMfaRequestHandler(AuthContextProperties authContextProperties,
                                              AuthResponseWriter responseWriter,
                                              ApplicationContext applicationContext,
                                              MfaStateMachineIntegrator stateMachineIntegrator,
                                              AuthUrlProvider authUrlProvider) {
        this.authContextProperties = authContextProperties;
        this.responseWriter = responseWriter;
        this.applicationContext = applicationContext;
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.mfaSettings = authContextProperties.getMfa();
        this.authUrlProvider = authUrlProvider;

            }

    @Override
    public void handleRequest(MfaRequestType requestType, HttpServletRequest request,
                              HttpServletResponse response, FactorContext context,
                              FilterChain filterChain) throws ServletException, IOException {

        String sessionId = context.getMfaSessionId();
        long startTime = System.currentTimeMillis();

        try {
            
            processRequestByType(requestType, request, response, context, filterChain);

            long processingTime = System.currentTimeMillis() - startTime;
            
        } catch (Exception e) {
            log.error("Error in unified State Machine request handling for session: {}", sessionId, e);
            handleProcessingError(request, response, context, e);
        }
    }

    @Override
    public void handleTerminalContext(HttpServletRequest request, HttpServletResponse response,
                                      FactorContext context) throws ServletException, IOException {
        String sessionId = context.getMfaSessionId();
        MfaState currentState = context.getCurrentState();

        MfaState latestState = stateMachineIntegrator.getCurrentState(sessionId);
        if (latestState != currentState) {
            log.warn("State mismatch detected: context={}, stateMachine={}", currentState, latestState);
            context.changeState(latestState);
            currentState = latestState;
        }

        Map<String, Object> responseBody = createBaseResponse(context);
        responseBody.put("terminal", true);
        responseBody.put("finalState", currentState.name());

        handleTerminalState(currentState, request, response, responseBody);

        scheduleStateMachineCleanup(sessionId);
    }

    private void handleTerminalState(MfaState state, HttpServletRequest request,
                                     HttpServletResponse response, Map<String, Object> responseBody) throws IOException {
        String contextPath = request.getContextPath();
        String requestUri = request.getRequestURI();

        switch (state) {
            case MFA_SUCCESSFUL -> {
                responseBody.put("status", "MFA_COMPLETED");
                responseBody.put("message", "MFA 인증이 성공적으로 완료되었습니다.");
                responseBody.put("redirectUrl", contextPath + "/home");
                responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
            }
            case MFA_NOT_REQUIRED -> {
                responseBody.put("status", "MFA_NOT_REQUIRED");
                responseBody.put("message", "MFA가 필요하지 않습니다.");
                responseBody.put("redirectUrl", contextPath + "/home");
                responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
            }
            case MFA_FAILED_TERMINAL, MFA_RETRY_LIMIT_EXCEEDED -> {
                responseBody.put("status", "MFA_FAILED");
                responseBody.put("message", "MFA 인증이 실패했습니다.");
                responseBody.put("redirectUrl", contextPath + "/loginForm");
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                        "MFA_FAILED", "MFA 인증 실패", requestUri, responseBody);
            }
            case MFA_SESSION_EXPIRED -> {
                responseBody.put("status", "SESSION_EXPIRED");
                responseBody.put("message", "MFA 세션이 만료되었습니다.");
                responseBody.put("redirectUrl", contextPath + "/loginForm");
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                        "SESSION_EXPIRED", "세션 만료", requestUri, responseBody);
            }
            case MFA_CANCELLED -> {
                responseBody.put("status", "MFA_CANCELLED");
                responseBody.put("message", "사용자에 의해 MFA가 취소되었습니다.");
                responseBody.put("redirectUrl", contextPath + "/loginForm");
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        "MFA_CANCELLED", "MFA 취소", requestUri, responseBody);
            }
            case MFA_SYSTEM_ERROR -> {
                responseBody.put("status", "SYSTEM_ERROR");
                responseBody.put("message", "시스템 오류가 발생했습니다.");
                responseBody.put("redirectUrl", contextPath + "/loginForm");
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "SYSTEM_ERROR", "시스템 오류", requestUri, responseBody);
            }
            default -> {
                responseBody.put("status", "UNKNOWN_TERMINAL_STATE");
                responseBody.put("message", "알 수 없는 터미널 상태입니다: " + state);
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "UNKNOWN_STATE", "알 수 없는 상태", requestUri, responseBody);
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
        errorResponse.put("message", "MFA 처리 중 시스템 오류가 발생했습니다.");
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
                        "지원하지 않는 요청 타입입니다: " + requestType.getDescription());
                errorResponse.put("requestType", requestType.name());
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        "UNSUPPORTED_REQUEST", "Unsupported request type", request.getRequestURI(), errorResponse);
                break;
        }
    }

    private void handleFactorSelection(HttpServletRequest request, HttpServletResponse response,
                                       FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();

        String selectedFactor = extractAndValidateSelectedFactor(request, response, context);
        if (selectedFactor == null) return; 

        if (sendFactorSelectionEvent(context, request, selectedFactor)) {
            handleFactorSelectionSuccess(request, response, context, selectedFactor);
        } else {
            handleFactorSelectionFailure(request, response, context);
        }
    }

    private void handleChallengeInitiation(HttpServletRequest request, HttpServletResponse response,
                                           FactorContext context) throws IOException {
        String sessionId = context.getMfaSessionId();
        MfaSettings mfaSettings = authContextProperties.getMfa();

        if (!isValidStateForChallengeInitiation(context)) {
            handleInvalidStateError(request, response, context, "INVALID_STATE_FOR_CHALLENGE",
                    "챌린지 시작이 불가능한 상태입니다. 현재 상태: " + context.getCurrentState());
            return;
        }

        if (context.getCurrentProcessingFactor() == null) {
            handleInvalidStateError(request, response, context, "NO_PROCESSING_FACTOR",
                    "처리할 팩터가 선택되지 않았습니다.");
            return;
        }

        if (hasActiveChallengeForFactor(context)) {

            Object challengeTime = context.getAttribute("challengeInitiatedAt");
            Instant challengeStart = MfaTimeUtils.fromMillis((Long) challengeTime);
            Duration remaining = MfaTimeUtils.getRemainingChallengeTime(challengeStart, mfaSettings);

            Map<String, Object> reuseResponse = createSuccessResponse(context, "CHALLENGE_REUSED",
                    "기존 챌린지를 재사용합니다.");
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
                    "챌린지가 시작되었습니다.");
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
                    "챌린지 시작에 실패했습니다.");
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
                    "MFA가 사용자에 의해 취소되었습니다.");
            cancelResponse.put("cancelledAt", System.currentTimeMillis());
            cancelResponse.put("redirectUrl", request.getContextPath() + "/loginForm");

            responseWriter.writeSuccessResponse(response, cancelResponse, HttpServletResponse.SC_OK);

            scheduleStateMachineCleanup(sessionId);
        } else {
            handleInvalidStateError(request, response, context, "CANCELLATION_FAILED",
                    "MFA 취소에 실패했습니다.");
        }
    }

    private String extractAndValidateSelectedFactor(HttpServletRequest request, HttpServletResponse response,
                                                    FactorContext context) throws IOException {
        String selectedFactor = request.getParameter("factor");
        if (selectedFactor == null || selectedFactor.trim().isEmpty()) {
            Map<String, Object> errorResponse = createErrorResponse(context, "MISSING_FACTOR_PARAMETER",
                    "선택할 팩터를 지정해주세요.");
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

            return stateMachineIntegrator.sendEvent(MfaEvent.FACTOR_SELECTED, context, request);
        } catch (Exception e) {
            log.error("Failed to send factor selection event", e);
            return false;
        }
    }

    private void handleFactorSelectionSuccess(HttpServletRequest request, HttpServletResponse response,
                                              FactorContext context, String selectedFactor) throws IOException {
        Map<String, Object> successResponse = createSuccessResponse(context, "FACTOR_SELECTED",
                "팩터가 성공적으로 선택되었습니다.");
        successResponse.put("selectedFactor", selectedFactor);
        successResponse.put("nextStepUrl", determineNextStepUrl(context, request));
        successResponse.put("factorSelectedAt", System.currentTimeMillis());

        responseWriter.writeSuccessResponse(response, successResponse, HttpServletResponse.SC_OK);
    }

    private void handleFactorSelectionFailure(HttpServletRequest request, HttpServletResponse response,
                                              FactorContext context) throws IOException {
        handleInvalidStateError(request, response, context, "FACTOR_SELECTION_REJECTED",
                "팩터 선택이 거부되었습니다.");
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
                "요청 처리 중 오류가 발생했습니다.");
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
        if (context.getCurrentProcessingFactor() == null) {
            return request.getContextPath() + authUrlProvider.getMfaSelectFactor();
        }

        return switch (context.getCurrentProcessingFactor()) {
            case OTT -> request.getContextPath() +
                    authUrlProvider.getOttRequestCodeUi();
            case PASSKEY -> request.getContextPath() +
                    authUrlProvider.getPasskeyChallengeUi();
            default -> request.getContextPath() + authUrlProvider.getMfaSelectFactor();
        };
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