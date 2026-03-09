package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.*;

@Slf4j

public final class PrimaryAuthenticationSuccessHandler extends AbstractMfaAuthenticationSuccessHandler {

    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthResponseWriter responseWriter;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;
    private final AuthUrlProvider authUrlProvider;
    private final ApplicationContext applicationContext;

    public PrimaryAuthenticationSuccessHandler(MfaPolicyProvider mfaPolicyProvider, @Nullable TokenService tokenService,
                                               AuthResponseWriter responseWriter, AuthContextProperties authContextProperties,
                                               ApplicationContext applicationContext, MfaStateMachineIntegrator stateMachineIntegrator,
                                               MfaSessionRepository sessionRepository, AuthUrlProvider authUrlProvider,
                                               ZeroTrustEventPublisher zeroTrustEventPublisher,
                                               ZeroTrustActionRepository actionRedisRepository,
                                               SecurityLearningService securityLearningService,
                                               IBlockedUserRecorder blockedUserRecorder,
                                               BlockMfaStateStore blockMfaStateStore,
                                               CentralAuditFacade centralAuditFacade) {
        super(tokenService, responseWriter, sessionRepository, stateMachineIntegrator, authContextProperties,
                zeroTrustEventPublisher, actionRedisRepository, securityLearningService, applicationContext, authUrlProvider,
                blockedUserRecorder, blockMfaStateStore, centralAuditFacade);
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

        String username = authentication.getName();
        String mfaSessionId = sessionRepository.getSessionId(request);
        if (mfaSessionId == null) {
            handleInvalidContext(response, request, "SESSION_ID_NOT_FOUND", "MFA session ID not found.", authentication);
            return;
        }

        FactorContext factorContext = stateMachineIntegrator.loadFactorContext(mfaSessionId);
        if (factorContext == null || !Objects.equals(factorContext.getUsername(), authentication.getName())) {
            log.error("Invalid FactorContext or username mismatch after primary authentication.");
            handleInvalidContext(response, request, "INVALID_CONTEXT", "Authentication context is invalid or user information does not match.", authentication);
            return;
        }

        MfaDecision decision = mfaPolicyProvider.evaluateInitialMfaRequirement(factorContext);

        Map<String, Object> headers = new HashMap<>();
        headers.put("mfaDecision", decision);
        headers.put("request", request);

        try {
            boolean initialized = stateMachineIntegrator.sendEvent(MfaEvent.PRIMARY_AUTH_SUCCESS, factorContext, request, headers);

            if (!initialized) {
                log.error("Failed to initialize MFA for session: {}", mfaSessionId);
                handleConfigError(response, request, factorContext, "MFA initialization failed.");
                return;
            }

        } catch (Exception e) {

            log.error("Exception during PRIMARY_AUTH_SUCCESS for session: {}: {}",
                    mfaSessionId, e.getMessage(), e);

            processErrorEventRecommendation(factorContext, request, mfaSessionId);

            handleConfigError(response, request, factorContext, "Error occurred during MFA initialization.");
            return;
        }

        if (decision.isAllowed()) {
            handleFinalAuthenticationSuccess(request, response, authentication, factorContext);
            return;
        }

        if (decision.isBlocked() || decision.isEscalated()) {
            log.error("Authentication blocked/escalated for user: {} - Reason: {}",
                    factorContext.getUsername(), decision.getReason());

            FactorContext blockedContext = stateMachineIntegrator.loadFactorContext(mfaSessionId);
            if (blockedContext == null) {
                handleInvalidContext(response, request, "CONTEXT_LOST", "MFA context lost during processing.", authentication);
                return;
            }

            handleAuthenticationBlocked(request, response, blockedContext);
            return;
        }

        boolean nextEventSent = sendNextMfaEvent(decision, mfaSessionId, request);
        if (!nextEventSent) {
            log.error("Failed to send next MFA event for session: {}", mfaSessionId);
            handleConfigError(response, request, factorContext, "Failed to send MFA event.");
            return;
        }

        FactorContext finalFactorContext = stateMachineIntegrator.loadFactorContext(mfaSessionId);
        if (finalFactorContext == null) {
            handleInvalidContext(response, request, "CONTEXT_LOST", "MFA context lost during processing.", authentication);
            return;
        }

        MfaState currentState = finalFactorContext.getCurrentState();

        switch (currentState) {
            case MFA_NOT_REQUIRED, MFA_SUCCESSFUL:
                handleFinalAuthenticationSuccess(request, response, authentication, finalFactorContext);
                break;

            case AWAITING_FACTOR_SELECTION:
                handleFactorSelectionRequired(request, response, finalFactorContext);
                break;

            case FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION:
                handleDirectChallenge(request, response, finalFactorContext);
                break;

            case PRIMARY_AUTHENTICATION_COMPLETED:
                log.error("State remained PRIMARY_AUTHENTICATION_COMPLETED for user: {}. Next event may have failed.", username);
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, factorContext, request);
                handleConfigError(response, request, finalFactorContext, "State did not transition to next step after MFA initialization.");
                break;

            default:
                log.error("Unexpected FactorContext state ({}) for user {} after policy evaluation",
                        currentState, username);
                stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, factorContext, request);
                handleConfigError(response, request, finalFactorContext, "Unexpected state during MFA processing.");
        }
    }

    private void handleFactorSelectionRequired(HttpServletRequest request, HttpServletResponse response,
                                               FactorContext factorContext) throws IOException {
        Map<String, Object> responseBody = createMfaResponseBody(
                "MFA_REQUIRED_SELECT_FACTOR",
                "Additional authentication is required. Please select an authentication method.",
                factorContext,
                request.getContextPath() + authUrlProvider.getMfaSelectFactor(),
                2
        );

        java.util.List<Map<String, Object>> factorDetails = factorContext.getAvailableFactors().stream()
                .map(authType -> createFactorDetail(authType.name()))
                .toList();
        responseBody.put("availableFactors", factorDetails);
        responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
    }

    private void handleDirectChallenge(HttpServletRequest request, HttpServletResponse response,
                                       FactorContext factorContext) throws IOException {
        AuthType nextFactor = factorContext.getCurrentProcessingFactor();
        String nextUiPageUrl = determineChallengeUrl(factorContext, request);

        Map<String, Object> responseBody = createMfaResponseBody(
                "MFA_REQUIRED",
                "Additional authentication is required.",
                factorContext,
                nextUiPageUrl,
                2
        );
        responseBody.put("nextFactorType", nextFactor.name());
        responseBody.put("nextStepId", factorContext.getCurrentStepId());

        responseWriter.writeSuccessResponse(response, responseBody, HttpServletResponse.SC_OK);
    }

    private Map<String, Object> createMfaResponseBody(String status, String message,
                                                      FactorContext factorContext, String nextStepUrl, int currentStep) {
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", status);
        responseBody.put("message", message);
        responseBody.put("mfaSessionId", factorContext.getMfaSessionId());
        responseBody.put("nextStepUrl", nextStepUrl);
        responseBody.put("progress", createProgressInfo(currentStep, 3));

        return responseBody;
    }

    private void handleInvalidContext(HttpServletResponse response, HttpServletRequest request,
                                      String errorCode, String logMessage,
                                      @Nullable Authentication authentication) throws IOException {
        log.error("Invalid FactorContext using {} repository: {}. User: {}",
                sessionRepository.getRepositoryType(), logMessage,
                (authentication != null ? authentication.getName() : "Unknown"));

        String oldSessionId = sessionRepository.getSessionId(request);
        if (oldSessionId != null) {
            try {
                stateMachineIntegrator.releaseStateMachine(oldSessionId);
                sessionRepository.removeSession(oldSessionId, request, response);
            } catch (Exception e) {
                log.error("Failed to cleanup invalid session using {} repository: {}",
                        sessionRepository.getRepositoryType(), oldSessionId, e);
            }
        }

        Map<String, Object> errorResponse = new HashMap<>();

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, errorCode,
                "MFA session context error: " + logMessage, request.getRequestURI(), errorResponse);
    }

    private String determineChallengeUrl(FactorContext ctx, HttpServletRequest request) {
        if (ctx.getCurrentProcessingFactor() == null) {
            return request.getContextPath() + authUrlProvider.getMfaSelectFactor();
        }

        return switch (ctx.getCurrentProcessingFactor()) {
            case MFA_OTT -> request.getContextPath() +
                    authUrlProvider.getOttRequestCodeUi();
            case MFA_PASSKEY -> request.getContextPath() +
                    authUrlProvider.getPasskeyChallengeUi();
            default -> request.getContextPath() + authUrlProvider.getMfaSelectFactor();
        };
    }

    private void handleAuthenticationBlocked(HttpServletRequest request,
                                             HttpServletResponse response,
                                             FactorContext ctx) throws IOException {
        String blockReason = (String) ctx.getAttribute("blockReason");
        Double riskScore = (Double) ctx.getAttribute("aiRiskScore");

        log.error("SECURITY_ALERT: Authentication blocked for user '{}' - Risk Score: {}, Reason: {}",
                ctx.getUsername(), riskScore, blockReason);

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", "AUTHENTICATION_BLOCKED");
        errorResponse.put("blocked", true);
        errorResponse.put("message", "Authentication has been blocked by security policy. Please contact the administrator.");
        errorResponse.put("supportContact", "security@example.com");
        errorResponse.put("username", ctx.getUsername());
        errorResponse.put("timestamp", System.currentTimeMillis());

        errorResponse.put("riskScore", riskScore);
        errorResponse.put("reason", blockReason);

        try {
            stateMachineIntegrator.releaseStateMachine(ctx.getMfaSessionId());
            sessionRepository.removeSession(ctx.getMfaSessionId(), request, response);
        } catch (Exception e) {
            log.error("Failed to cleanup blocked session: {}", ctx.getMfaSessionId(), e);
        }

        responseWriter.writeErrorResponse(
                response,
                HttpServletResponse.SC_FORBIDDEN,
                "AUTHENTICATION_BLOCKED",
                "Authentication has been blocked by security policy. Please contact the administrator.",
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

            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("mfaSessionId", ctx.getMfaSessionId());

            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    errorCode, message, request.getRequestURI(), errorDetails);
        } else {
            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    errorCode, message, request.getRequestURI());
        }
    }

    private boolean sendNextMfaEvent(MfaDecision decision, String mfaSessionId, HttpServletRequest request) {
        FactorContext context = stateMachineIntegrator.loadFactorContext(mfaSessionId);
        if (context == null) {
            log.error("FactorContext not found for session: {}", mfaSessionId);
            return false;
        }

        if (decision.isBlocked()) {
            return true;
        }

        if (!decision.isRequired()) {
            boolean sent = stateMachineIntegrator.sendEvent(MfaEvent.MFA_NOT_REQUIRED, context, request);
            return sent;
        }

        AuthType autoSelectedFactor = determineAutoFactor(context, decision);
        if (autoSelectedFactor == null) {
            log.error("Failed to determine auto factor for session: {}", mfaSessionId);
            return false;
        }

        context.setCurrentProcessingFactor(autoSelectedFactor);

        setCurrentStepId(context, autoSelectedFactor);

        boolean sent = stateMachineIntegrator.sendEvent(MfaEvent.INITIATE_CHALLENGE_AUTO, context, request);
        return sent;
    }

    private AuthType determineAutoFactor(FactorContext context, MfaDecision decision) {
        String sessionId = context.getMfaSessionId();

        if (decision.getRequiredFactors() != null && !decision.getRequiredFactors().isEmpty()) {
            AuthType firstFactor = decision.getRequiredFactors().getFirst();

            if (context.getAvailableFactors() != null &&
                    context.getAvailableFactors().contains(firstFactor)) {
                return firstFactor;
            }
        }

        Set<AuthType> availableFactors = context.getAvailableFactors();
        if (availableFactors != null && !availableFactors.isEmpty()) {

            List<AuthType> factorList = new ArrayList<>(availableFactors);
            AuthType firstAvailable = factorList.getFirst();
            return firstAvailable;
        }

        log.error("No available factors for auto-selection in session: {}", sessionId);
        return null;
    }

    private void setCurrentStepId(FactorContext context, AuthType factorType) {
        try {

            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);

            AuthenticationFlowConfig flowConfig = platformConfig.getFlows().stream()
                    .filter(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()))
                    .findFirst()
                    .orElse(null);

            if (flowConfig == null) {
                log.error("MFA FlowConfig not found, stepId will not be set");
                return;
            }

            AuthenticationStepConfig nextStep = flowConfig.getStepConfigs().stream()
                    .filter(step -> factorType.name().equalsIgnoreCase(step.getType()))
                    .findFirst()
                    .orElse(null);

            if (nextStep != null) {
                context.setCurrentStepId(nextStep.getStepId());
            } else {
                log.error("No step config found for factor: {} in session: {}",
                        factorType, context.getMfaSessionId());
            }
        } catch (Exception e) {
            log.error("Error setting currentStepId for factor: {} in session: {}",
                    factorType, context.getMfaSessionId(), e);
        }
    }
}