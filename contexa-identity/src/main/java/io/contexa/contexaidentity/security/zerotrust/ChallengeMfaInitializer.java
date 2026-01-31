package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Slf4j
public class ChallengeMfaInitializer {

    private final MfaSessionRepository sessionRepository;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final PlatformConfig platformConfig;

    private final BytesKeyGenerator sessionIdGenerator = KeyGenerators.secureRandom(32);

    private static final String CHALLENGE_FLOW_TYPE_NAME = "mfa";
    private static final String CHALLENGE_REASON_ATTRIBUTE = "challengeReason";
    private static final String CHALLENGE_INITIATED_ATTRIBUTE = "challengeInitiated";

    public ChallengeMfaInitializer(
            MfaSessionRepository sessionRepository,
            MfaStateMachineIntegrator stateMachineIntegrator,
            MfaPolicyProvider mfaPolicyProvider,
            PlatformConfig platformConfig) {
        this.sessionRepository = sessionRepository;
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.mfaPolicyProvider = mfaPolicyProvider;
        this.platformConfig = platformConfig;
    }

    public FactorContext initializeChallengeFlow(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {

        String mfaSessionId = generateSecureSessionId();

        FactorContext context = new FactorContext(
                mfaSessionId,
                authentication,
                MfaState.NONE,
                CHALLENGE_FLOW_TYPE_NAME
        );

        enhanceFactorContextWithSecurityInfo(context, request);
        context.setAttribute(CHALLENGE_INITIATED_ATTRIBUTE, true);
        context.setAttribute(CHALLENGE_REASON_ATTRIBUTE, "ZERO_TRUST_ADAPTIVE");
        context.setAttribute(FactorContextAttributes.Timestamps.PRIMARY_AUTH_COMPLETED_AT, System.currentTimeMillis());

        try {
            stateMachineIntegrator.initializeStateMachine(context, request, response);

            MfaDecision decision = createChallengeMfaDecision(context);

            Map<String, Object> headers = new HashMap<>();
            headers.put("mfaDecision", decision);
            headers.put("request", request);
            headers.put("challengeFlow", true);

            boolean initialized = stateMachineIntegrator.sendEvent(
                    MfaEvent.ADAPTIVE_MFA_REQUIRED, context, request, headers);

            if (!initialized) {
                log.error("Failed to send ADAPTIVE_MFA_REQUIRED event for session: {}", mfaSessionId);
                cleanupFailedSession(mfaSessionId, request, response);
                throw new ChallengeMfaInitializationException(
                        "Failed to initialize state machine with ADAPTIVE_MFA_REQUIRED event");
            }

            FactorContext updatedContext = stateMachineIntegrator.loadFactorContext(mfaSessionId);
            if (updatedContext != null) {
                context = updatedContext;
            } else {
                log.warn("Could not load updated context from state machine, setting availableFactors manually for session: {}", mfaSessionId);
                AuthenticationFlowConfig mfaFlow = getMfaFlowConfig();
                if (mfaFlow != null) {
                    Set<AuthType> availableFactors = new LinkedHashSet<>(mfaFlow.getRegisteredFactorOptions().keySet());
                    context.setAttribute(FactorContextAttributes.Policy.AVAILABLE_FACTORS, availableFactors);
                }
            }

            sendNextMfaEvent(decision, context, request);

            FactorContext refreshedContext = stateMachineIntegrator.loadFactorContext(mfaSessionId);
            if (refreshedContext == null) {
                log.warn("FactorContext could not be loaded from state machine for session: {}, returning local context", mfaSessionId);
                return context;
            }

            return refreshedContext;

        } catch (ChallengeMfaInitializationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to initialize challenge MFA flow for session: {}", mfaSessionId, e);
            cleanupFailedSession(mfaSessionId, request, response);
            throw new ChallengeMfaInitializationException("Challenge MFA initialization failed", e);
        }
    }

    private MfaDecision createChallengeMfaDecision(FactorContext context) {
        MfaDecision policyDecision = mfaPolicyProvider.evaluateInitialMfaRequirement(context);

        if (policyDecision.isRequired()) {
            return policyDecision;
        }

        return MfaDecision.builder()
                .required(true)
                .type(MfaDecision.DecisionType.CHALLENGED)
                .reason("Zero Trust CHALLENGE action requires additional verification")
                .metadata(Map.of(
                        "challengeFlow", true,
                        "zeroTrustTriggered", true
                ))
                .build();
    }

    private void sendNextMfaEvent(MfaDecision decision, FactorContext context, HttpServletRequest request) {
        AuthType autoSelectedFactor = determineAutoFactor(context, decision);
        if (autoSelectedFactor == null) {
            log.error("Failed to determine auto factor for challenge session: {}", context.getMfaSessionId());
            boolean sent = stateMachineIntegrator.sendEvent(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, context, request);
            if (!sent) {
                log.error("Failed to send MFA_REQUIRED_SELECT_FACTOR event for session: {}", context.getMfaSessionId());
            }
            return;
        }

        context.setCurrentProcessingFactor(autoSelectedFactor);
        setCurrentStepId(context, autoSelectedFactor);

        boolean sent = stateMachineIntegrator.sendEvent(MfaEvent.INITIATE_CHALLENGE_AUTO, context, request);
        if (!sent) {
            log.error("Failed to send INITIATE_CHALLENGE_AUTO event, falling back to factor selection");
            stateMachineIntegrator.sendEvent(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, context, request);
        }
    }

    private AuthType determineAutoFactor(FactorContext context, MfaDecision decision) {
        if (decision.getRequiredFactors() != null && !decision.getRequiredFactors().isEmpty()) {
            AuthType firstFactor = decision.getRequiredFactors().getFirst();
            Set<AuthType> availableFactors = context.getAvailableFactors();
            if (availableFactors != null && availableFactors.contains(firstFactor)) {
                return firstFactor;
            }
        }

        Set<AuthType> availableFactors = context.getAvailableFactors();
        if (availableFactors != null && !availableFactors.isEmpty()) {
            List<AuthType> factorList = new ArrayList<>(availableFactors);
            return factorList.getFirst();
        }

        AuthenticationFlowConfig mfaFlow = getMfaFlowConfig();
        if (mfaFlow != null) {
            Set<AuthType> configuredFactors = new LinkedHashSet<>(mfaFlow.getRegisteredFactorOptions().keySet());
            if (!configuredFactors.isEmpty()) {
                context.setAttribute(FactorContextAttributes.Policy.AVAILABLE_FACTORS, configuredFactors);
                return configuredFactors.iterator().next();
            }
        }

        log.error("No available factors for auto-selection in challenge session: {}", context.getMfaSessionId());
        return null;
    }

    private void setCurrentStepId(FactorContext context, AuthType factorType) {
        AuthenticationFlowConfig mfaFlow = getMfaFlowConfig();
        if (mfaFlow == null) {
            log.warn("MFA FlowConfig not found, stepId will not be set for session: {}", context.getMfaSessionId());
            return;
        }

        AuthenticationStepConfig stepConfig = mfaFlow.getStepConfigs().stream()
                .filter(step -> factorType.name().equalsIgnoreCase(step.getType()))
                .findFirst()
                .orElse(null);

        if (stepConfig != null) {
            context.setCurrentStepId(stepConfig.getStepId());
        } else {
            log.warn("No step config found for factor: {} in session: {}",
                    factorType, context.getMfaSessionId());
        }
    }

    private AuthenticationFlowConfig getMfaFlowConfig() {
        return platformConfig.getFlows().stream()
                .filter(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()))
                .findFirst()
                .orElse(null);
    }

    private void enhanceFactorContextWithSecurityInfo(FactorContext context, HttpServletRequest request) {
        String deviceId = getOrCreateDeviceId(request);
        context.setAttribute(FactorContextAttributes.DeviceAndSession.DEVICE_ID, deviceId);
        context.setAttribute(FactorContextAttributes.DeviceAndSession.CLIENT_IP, getClientIpAddress(request));
        context.setAttribute(FactorContextAttributes.DeviceAndSession.USER_AGENT, request.getHeader("User-Agent"));
        context.setAttribute(FactorContextAttributes.Timestamps.LOGIN_TIMESTAMP, System.currentTimeMillis());
    }

    private String generateSecureSessionId() {
        byte[] bytes = sessionIdGenerator.generateKey();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String getOrCreateDeviceId(HttpServletRequest request) {
        String deviceId = request.getHeader("X-Device-Id");
        if (StringUtils.hasText(deviceId) && isValidDeviceId(deviceId)) {
            return deviceId;
        }
        return generateSecureSessionId();
    }

    private boolean isValidDeviceId(String deviceId) {
        return deviceId.matches("^[a-zA-Z0-9_-]{22,}$") ||
                deviceId.matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String[] headers = {
                "X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP",
                "HTTP_X_FORWARDED_FOR", "HTTP_X_FORWARDED", "HTTP_X_CLUSTER_CLIENT_IP",
                "HTTP_CLIENT_IP", "HTTP_FORWARDED_FOR", "HTTP_FORWARDED", "HTTP_VIA", "REMOTE_ADDR"
        };

        for (String header : headers) {
            String ip = request.getHeader(header);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                return ip.split(",")[0].trim();
            }
        }

        return request.getRemoteAddr();
    }

    private void cleanupFailedSession(String mfaSessionId, HttpServletRequest request, HttpServletResponse response) {
        try {
            if (sessionRepository.existsSession(mfaSessionId)) {
                stateMachineIntegrator.releaseStateMachine(mfaSessionId);
                sessionRepository.removeSession(mfaSessionId, request, response);
            }
        } catch (Exception e) {
            log.warn("Failed to cleanup failed challenge session: {}", mfaSessionId, e);
        }
    }

    public static class ChallengeMfaInitializationException extends RuntimeException {
        public ChallengeMfaInitializationException(String message) {
            super(message);
        }

        public ChallengeMfaInitializationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
