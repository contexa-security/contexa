package io.contexa.contexaidentity.controller;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Deprecated
@RestController
@RequestMapping("/api/mfa")
@RequiredArgsConstructor
@ConditionalOnBean({MfaStateMachineIntegrator.class, AuthUrlProvider.class})
public class MfaApiController {

    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final AuthUrlProvider authUrlProvider;

    @PostMapping("/select-factor")
    public ResponseEntity<Map<String, Object>> selectFactor(@RequestBody Map<String, String> request,
                                                            HttpServletRequest httpRequest) {
        String factorType = request.get("factor");

        if (!StringUtils.hasText(factorType)) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "MISSING_FACTOR",
                    "Factor type is required", null);
        }

        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(httpRequest);

        if (!isValidMfaContext(ctx)) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_MFA_SESSION",
                    "Invalid or expired MFA session", ctx);
        }

        if (ctx.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
            log.warn("Factor selection attempted in invalid state: {} for session: {}",
                    ctx.getCurrentState(), ctx.getMfaSessionId());
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_STATE",
                    "Cannot select factor in current state: " + ctx.getCurrentState(), ctx);
        }

        AuthType requestedFactorType;
        try {
            requestedFactorType = AuthType.valueOf(factorType.toUpperCase());
        } catch (IllegalArgumentException e) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_FACTOR_TYPE",
                    "Invalid factor type: " + factorType, ctx);
        }

        if (!ctx.isFactorAvailable(requestedFactorType)) {
            log.warn("User {} attempted to select unavailable factor: {}. DSL available factors: {}",
                    ctx.getUsername(), requestedFactorType, ctx.getAvailableFactors());
            return createErrorResponse(HttpStatus.BAD_REQUEST, "FACTOR_NOT_AVAILABLE",
                    "시스템에서 지원하지 않는 팩터입니다: " + requestedFactorType, ctx);
        }

        try {
            
            ctx.setAttribute("selectedFactorType", requestedFactorType.name());

            boolean accepted = stateMachineIntegrator.sendEvent(
                    MfaEvent.FACTOR_SELECTED, ctx, httpRequest
            );

            if (accepted) {
                String nextStepUrl = determineNextStepUrl(ctx, httpRequest);

                Map<String, Object> successResponse = createSuccessResponse(
                        "FACTOR_SELECTED", "Factor selected successfully", ctx);
                successResponse.put("selectedFactor", requestedFactorType.name());
                successResponse.put("nextStepUrl", nextStepUrl);
                successResponse.put("currentState", ctx.getCurrentState().name());

                return ResponseEntity.ok(successResponse);
            } else {
                log.error("State Machine rejected FACTOR_SELECTED event for session: {} in state: {}",
                        ctx.getMfaSessionId(), ctx.getCurrentState());
                return createErrorResponse(HttpStatus.BAD_REQUEST, "EVENT_REJECTED",
                        "Invalid state for factor selection", ctx);
            }

        } catch (Exception e) {
            log.error("Error selecting factor {} for session: {}", factorType, ctx.getMfaSessionId(), e);

            try {
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, ctx, httpRequest);
            } catch (Exception eventError) {
                log.error("Failed to send SYSTEM_ERROR event", eventError);
            }

            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "FACTOR_SELECTION_FAILED",
                    "Failed to select factor", ctx);
        }
    }

    @PostMapping("/cancel")
    public ResponseEntity<Map<String, Object>> cancelMfa(HttpServletRequest httpRequest) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(httpRequest);

        if (!isValidMfaContext(ctx)) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_MFA_SESSION",
                    "Invalid or expired MFA session", null);
        }

        if (ctx.getCurrentState().isTerminal()) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "ALREADY_TERMINAL",
                    "MFA process is already completed or terminated", ctx);
        }

        try {
            
            boolean accepted = stateMachineIntegrator.sendEvent(
                    MfaEvent.USER_ABORTED_MFA, ctx, httpRequest
            );

            if (accepted) {
                Map<String, Object> successResponse = createSuccessResponse(
                        "MFA_CANCELLED", "MFA cancelled successfully", ctx);
                successResponse.put("redirectUrl", getContextPath(httpRequest) + authUrlProvider.getPrimaryLoginPage());

                stateMachineIntegrator.cleanupSession(httpRequest);

                return ResponseEntity.ok(successResponse);
            } else {
                log.warn("State Machine rejected USER_ABORTED_MFA event for session: {} in state: {}",
                        ctx.getMfaSessionId(), ctx.getCurrentState());
                return createErrorResponse(HttpStatus.BAD_REQUEST, "CANCELLATION_REJECTED",
                        "Cannot cancel MFA in current state: " + ctx.getCurrentState(), ctx);
            }

        } catch (Exception e) {
            log.error("Error cancelling MFA for session: {}", ctx.getMfaSessionId(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "CANCELLATION_FAILED",
                    "Failed to cancel MFA", ctx);
        }
    }

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getMfaStatus(HttpServletRequest httpRequest) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(httpRequest);

        if (!isValidMfaContext(ctx)) {
            return createErrorResponse(HttpStatus.NOT_FOUND, "NO_MFA_SESSION",
                    "No active MFA session found", null);
        }

        try {
            Map<String, Object> statusResponse = new HashMap<>();
            statusResponse.put("status", "ACTIVE");
            statusResponse.put("mfaSessionId", ctx.getMfaSessionId());
            statusResponse.put("username", ctx.getUsername());
            statusResponse.put("currentState", ctx.getCurrentState().name());
            statusResponse.put("flowType", ctx.getFlowTypeName());
            statusResponse.put("isTerminal", ctx.getCurrentState().isTerminal());
            statusResponse.put("availableFactors", ctx.getAvailableFactors());
            statusResponse.put("completedFactorsCount", ctx.getCompletedFactors().size());
            statusResponse.put("storageType", "UNIFIED_STATE_MACHINE");

            if (ctx.getCurrentProcessingFactor() != null) {
                statusResponse.put("currentProcessingFactor", ctx.getCurrentProcessingFactor().name());
                statusResponse.put("currentStepId", ctx.getCurrentStepId());
            }

            return ResponseEntity.ok(statusResponse);

        } catch (Exception e) {
            log.error("Error retrieving MFA status for session: {}", ctx.getMfaSessionId(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "STATUS_RETRIEVAL_FAILED",
                    "Failed to retrieve MFA status", ctx);
        }
    }

    @PostMapping("/request-ott-code")
    public ResponseEntity<Map<String, Object>> requestOttCode(HttpServletRequest httpRequest) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(httpRequest);

        if (!isValidMfaContext(ctx)) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_MFA_SESSION",
                    "Invalid or expired MFA session", null);
        }

        if (ctx.getCurrentProcessingFactor() != AuthType.OTT) {
            return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_FACTOR",
                    "OTT code request is only available during OTT factor processing", ctx);
        }

        try {
            
            boolean accepted = stateMachineIntegrator.sendEvent(
                    MfaEvent.INITIATE_CHALLENGE, ctx, httpRequest
            );

            if (accepted) {
                Map<String, Object> successResponse = createSuccessResponse(
                        "OTT_CODE_REQUESTED", "OTT code has been resent", ctx);

                return ResponseEntity.ok(successResponse);
            } else {
                return createErrorResponse(HttpStatus.BAD_REQUEST, "REQUEST_REJECTED",
                        "Cannot request OTT code in current state", ctx);
            }

        } catch (Exception e) {
            log.error("Error requesting OTT code for session: {}", ctx.getMfaSessionId(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "OTT_REQUEST_FAILED",
                    "Failed to request OTT code", ctx);
        }
    }

    @GetMapping("/context")
    public ResponseEntity<Map<String, Object>> getFactorContext(HttpServletRequest httpRequest) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(httpRequest);

        if (!isValidMfaContext(ctx)) {
            return createErrorResponse(HttpStatus.NOT_FOUND, "NO_MFA_SESSION",
                    "No active MFA session found", null);
        }

        try {
            Map<String, Object> contextResponse = new HashMap<>();
            contextResponse.put("mfaSessionId", ctx.getMfaSessionId());
            contextResponse.put("username", ctx.getUsername());
            contextResponse.put("currentState", ctx.getCurrentState().name());
            contextResponse.put("flowType", ctx.getFlowTypeName());
            contextResponse.put("isTerminal", ctx.getCurrentState().isTerminal());

            List<String> availableFactorNames = ctx.getAvailableFactors().stream()
                    .map(AuthType::name)
                    .collect(Collectors.toList());
            contextResponse.put("availableFactors", availableFactorNames);

            List<String> completedFactorNames = ctx.getCompletedFactors().stream()
                    .filter(step -> step.getAuthType() != null)
                    .map(step -> step.getAuthType().name())
                    .collect(Collectors.toList());
            contextResponse.put("completedFactors", completedFactorNames);
            contextResponse.put("completedFactorsCount", completedFactorNames.size());

            if (ctx.getCurrentProcessingFactor() != null) {
                contextResponse.put("currentProcessingFactor", ctx.getCurrentProcessingFactor().name());
                contextResponse.put("currentStepId", ctx.getCurrentStepId());
            }

            contextResponse.put("storageType", "UNIFIED_STATE_MACHINE");
            contextResponse.put("timestamp", System.currentTimeMillis());

            return ResponseEntity.ok(contextResponse);

        } catch (Exception e) {
            log.error("Error retrieving MFA context for session: {}", ctx.getMfaSessionId(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "CONTEXT_RETRIEVAL_FAILED",
                    "Failed to retrieve MFA context", ctx);
        }
    }

    @GetMapping("/config")
    public ResponseEntity<Map<String, Object>> getEndpointConfig() {
        try {
            
            Map<String, Object> config = authUrlProvider.getAllUiPageUrls();

            return ResponseEntity.ok(config);

        } catch (Exception e) {
            log.error("Error retrieving endpoint configuration", e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "CONFIG_RETRIEVAL_FAILED",
                    "Failed to retrieve endpoint configuration", null);
        }
    }

    private boolean isValidMfaContext(FactorContext ctx) {
        return ctx != null &&
                StringUtils.hasText(ctx.getUsername()) &&
                StringUtils.hasText(ctx.getMfaSessionId()) &&
                !ctx.getCurrentState().isTerminal();
    }

    private String determineNextStepUrl(FactorContext ctx, HttpServletRequest request) {
        String contextPath = getContextPath(request);
        AuthType currentFactor = ctx.getCurrentProcessingFactor();

        if (currentFactor == null) {
            return contextPath + authUrlProvider.getMfaSelectFactor();
        }

        return switch (currentFactor) {
            case OTT -> contextPath + authUrlProvider.getOttRequestCodeUi();
            case PASSKEY -> contextPath + authUrlProvider.getPasskeyChallengeUi();
            default -> {
                log.warn("Unknown factor type for next step determination: {}", currentFactor);
                yield contextPath + authUrlProvider.getMfaSelectFactor();
            }
        };
    }

    private Map<String, Object> createSuccessResponse(String status, String message, FactorContext ctx) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", status);
        response.put("message", message);
        response.put("timestamp", System.currentTimeMillis());
        response.put("storageType", "UNIFIED_STATE_MACHINE");

        if (ctx != null) {
            response.put("mfaSessionId", ctx.getMfaSessionId());
            response.put("currentState", ctx.getCurrentState().name());
        }

        return response;
    }

    private ResponseEntity<Map<String, Object>> createErrorResponse(HttpStatus status, String errorCode,
                                                                    String message, FactorContext ctx) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", errorCode);
        errorResponse.put("message", message);
        errorResponse.put("timestamp", System.currentTimeMillis());
        errorResponse.put("storageType", "UNIFIED_STATE_MACHINE");

        if (ctx != null) {
            errorResponse.put("mfaSessionId", ctx.getMfaSessionId());
            errorResponse.put("currentState", ctx.getCurrentState().name());
        }

        return ResponseEntity.status(status).body(errorResponse);
    }

    private String getContextPath(HttpServletRequest request) {
        return request.getContextPath();
    }
}