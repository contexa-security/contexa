package io.contexa.contexacore.verification.contract.prompt;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * Concrete round-level replay contract shared by TDD and HTTP runtime adapters.
 */
public record OfficialVerificationPromptContractRoundPlan(
        String roundKey,
        String requestPath,
        String clientIp,
        String browserUserAgent,
        String simulatedUserAgentLabel,
        String deviceAlias,
        OffsetDateTime observedAt,
        OfficialVerificationPromptContractSessionMode sessionMode,
        long cooldownBeforeRoundMs,
        String behaviorPhase,
        String anomalySignal,
        String expectationNote,
        List<String> semanticMarkers) {

    public OfficialVerificationPromptContractRoundPlan {
        if (roundKey == null || roundKey.isBlank()) {
            throw new IllegalArgumentException("roundKey must not be blank");
        }
        if (requestPath == null || requestPath.isBlank()) {
            throw new IllegalArgumentException("requestPath must not be blank");
        }
        if (clientIp == null || clientIp.isBlank()) {
            throw new IllegalArgumentException("clientIp must not be blank");
        }
        if (browserUserAgent == null || browserUserAgent.isBlank()) {
            throw new IllegalArgumentException("browserUserAgent must not be blank");
        }
        if (deviceAlias == null || deviceAlias.isBlank()) {
            throw new IllegalArgumentException("deviceAlias must not be blank");
        }
        if (observedAt == null) {
            throw new IllegalArgumentException("observedAt must not be null");
        }
        if (sessionMode == null) {
            throw new IllegalArgumentException("sessionMode must not be null");
        }
        if (behaviorPhase == null || behaviorPhase.isBlank()) {
            throw new IllegalArgumentException("behaviorPhase must not be blank");
        }
        if (cooldownBeforeRoundMs < 0L) {
            throw new IllegalArgumentException("cooldownBeforeRoundMs must not be negative");
        }
        simulatedUserAgentLabel = (simulatedUserAgentLabel == null || simulatedUserAgentLabel.isBlank())
                ? browserUserAgent
                : simulatedUserAgentLabel;
        anomalySignal = anomalySignal == null ? "NONE" : anomalySignal;
        expectationNote = expectationNote == null ? "" : expectationNote;
        semanticMarkers = semanticMarkers == null ? List.of() : List.copyOf(semanticMarkers);
    }

    public boolean anomalyExpected() {
        return !"NONE".equalsIgnoreCase(anomalySignal);
    }

    public boolean startsNewSession() {
        return sessionMode == OfficialVerificationPromptContractSessionMode.NEW_SESSION;
    }
}