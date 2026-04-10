package io.contexa.contexacore.autonomous.saas.learning.strategy;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Resolves detection strategy families from correlated learning observations.
 */
public class DefaultStrategyFamilyResolver implements StrategyFamilyResolver {

    static final String PATH_SEQUENCE_DIVERGENCE = "PATH_SEQUENCE_DIVERGENCE";
    static final String SESSION_ENTROPY_COLLAPSE = "SESSION_ENTROPY_COLLAPSE";
    static final String POST_MFA_SURFACE_JUMP = "POST_MFA_SURFACE_JUMP";
    static final String INITIAL_REQUEST_PROFILE_DELTA = "INITIAL_REQUEST_PROFILE_DELTA";
    static final String SCOPE_EXPANSION_SEQUENCE = "SCOPE_EXPANSION_SEQUENCE";

    @Override
    public StrategyFamilyResolution resolve(StrategyLearningObservation observation) {
        if (observation == null) {
            return StrategyFamilyResolution.unresolved();
        }
        if (isPostMfaSurfaceJump(observation)) {
            return resolved(POST_MFA_SURFACE_JUMP,
                    "MFA-validated review context moved directly into a sensitive or administrative surface.",
                    "The correlated observation ended with containment or confirmed malicious outcome after a post-MFA surface jump.");
        }
        if (isInitialRequestProfileDelta(observation)) {
            return resolved(INITIAL_REQUEST_PROFILE_DELTA,
                    "A new-device or thin-baseline request diverged on its initial privileged path.",
                    "The observation carries containment evidence on an early request profile change.");
        }
        if (isScopeExpansionSequence(observation)) {
            return resolved(SCOPE_EXPANSION_SEQUENCE,
                    "The request sequence expanded into a privileged or sensitive scope.",
                    "Privileged-flow or sensitive-scope evidence is present in the correlated observation.");
        }
        if (isPathSequenceDivergence(observation)) {
            return resolved(PATH_SEQUENCE_DIVERGENCE,
                    "Request-path evidence diverged from the normal access sequence and required extra prompt context.",
                    "Denied prompt context or suspicious path evidence was preserved in the joined observation.");
        }
        if (isSessionEntropyCollapse(observation)) {
            return resolved(SESSION_ENTROPY_COLLAPSE,
                    "Escalation telemetry rose while the session evidence collapsed onto a narrow privileged surface.",
                    "The observation shows concentrated path behavior with elevated escalation or containment telemetry.");
        }
        return StrategyFamilyResolution.unresolved();
    }

    private boolean isPostMfaSurfaceJump(StrategyLearningObservation observation) {
        return isSensitiveOrAdministrativeSurface(observation)
                && hasContainmentOrConfirmedAttack(observation)
                && (containsText(signalText(observation, "reasonCategory"), "mfa")
                || containsAnyEvidence(observation, "mfa", "MFA"));
    }

    private boolean isInitialRequestProfileDelta(StrategyLearningObservation observation) {
        return hasContainmentOrConfirmedAttack(observation)
                && truthy(signal(observation, "isNewDevice"))
                && (isSensitiveOrAdministrativeSurface(observation)
                || !truthy(signal(observation, "personalBaselineEstablished"))
                || !truthy(signal(observation, "organizationBaselineEstablished")));
    }

    private boolean isScopeExpansionSequence(StrategyLearningObservation observation) {
        boolean privilegedSignal = containsAnyToken(observation.signalKeys(), "privileged_flow", "privilege_abuse", "scope_expansion")
                || containsAnyText(listSignal(observation, "campaignThreatClasses"), "privilege_abuse")
                || containsAnyText(listSignal(observation, "deniedReasons"), "scope", "approval", "privilege");
        boolean sensitiveScope = truthy(signal(observation, "isSensitiveResource")) || isSensitiveOrAdministrativeSurface(observation);
        return hasContainmentOrConfirmedAttack(observation)
                && sensitiveScope
                && (privilegedSignal || containsText(signalText(observation, "requestPath"), "/roles", "/role", "/permission", "/policy", "/export", "/report", "/billing"));
    }

    private boolean isPathSequenceDivergence(StrategyLearningObservation observation) {
        boolean sequenceContext = observation.promptAuditLinked()
                || observation.deniedContextCount() > 0
                || hasListSignal(observation, "promptSectionSet")
                || hasListSignal(observation, "omittedSections");
        boolean suspiciousPath = containsAnyToken(observation.signalKeys(),
                "failed_login_burst",
                "impossible_travel",
                "new_device",
                "credential_reuse",
                "session_takeover_risk")
                || containsAnyText(listSignal(observation, "campaignThreatClasses"), "account_takeover", "credential_abuse", "session_hijack")
                || containsText(signalText(observation, "requestPath"), "/admin/", "/export", "/report", "/session", "/oauth");
        return hasContainmentOrConfirmedAttack(observation) && sequenceContext && suspiciousPath;
    }

    private boolean isSessionEntropyCollapse(StrategyLearningObservation observation) {
        boolean elevatedTelemetry = observation.layer1EscalationRate() >= 0.30d
                || observation.blockRate() >= 0.10d
                || observation.challengeRate() >= 0.20d;
        boolean narrowEvidence = observation.signalKeys().size() <= 1
                && !observation.promptAuditLinked()
                && observation.deniedContextCount() == 0;
        return elevatedTelemetry && narrowEvidence && isSensitiveOrAdministrativeSurface(observation);
    }

    private boolean isSensitiveOrAdministrativeSurface(StrategyLearningObservation observation) {
        String pathCategory = signalText(observation, "pathCategory");
        return equalsAny(pathCategory, "sensitive_data", "administration", "credential_management");
    }

    private boolean hasContainmentOrConfirmedAttack(StrategyLearningObservation observation) {
        return containsAny(normalize(observation.finalDisposition()), "confirmed_attack", "compromised", "malicious")
                || containsAny(normalize(observation.outcomeType()), "confirmed_attack", "incident_confirmed", "session_takeover")
                || containsAny(normalize(observation.finalAction()), "block", "challenge", "terminate", "lock")
                || containsAny(normalize(observation.feedbackType()), "false_negative", "false_positive");
    }

    private StrategyFamilyResolution resolved(String family, String... facts) {
        LinkedHashSet<String> merged = new LinkedHashSet<>();
        for (String fact : facts) {
            if (fact != null && !fact.isBlank()) {
                merged.add(fact);
            }
        }
        return new StrategyFamilyResolution(family, List.copyOf(merged));
    }

    private Object signal(StrategyLearningObservation observation, String key) {
        Map<String, Object> signals = observation.strategySignals();
        return signals != null ? signals.get(key) : null;
    }

    private String signalText(StrategyLearningObservation observation, String key) {
        Object value = signal(observation, key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
    }

    @SuppressWarnings("unchecked")
    private List<String> listSignal(StrategyLearningObservation observation, String key) {
        Object value = signal(observation, key);
        if (value instanceof List<?> list) {
            List<String> normalized = new ArrayList<>();
            for (Object item : list) {
                if (item != null) {
                    String text = String.valueOf(item).trim();
                    if (!text.isEmpty()) {
                        normalized.add(text);
                    }
                }
            }
            return List.copyOf(normalized);
        }
        return List.of();
    }

    private boolean hasListSignal(StrategyLearningObservation observation, String key) {
        return !listSignal(observation, key).isEmpty();
    }

    private boolean truthy(Object value) {
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (value instanceof String text) {
            return Boolean.parseBoolean(text.trim());
        }
        return false;
    }

    private boolean containsAnyToken(List<String> tokens, String... candidates) {
        if (tokens == null || tokens.isEmpty()) {
            return false;
        }
        for (String token : tokens) {
            if (containsAny(normalize(token), candidates)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsAnyText(List<String> values, String... candidates) {
        if (values == null || values.isEmpty()) {
            return false;
        }
        for (String value : values) {
            if (containsText(value, candidates)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsAnyEvidence(StrategyLearningObservation observation, String... candidates) {
        for (String fact : observation.evidenceFacts()) {
            if (containsText(fact, candidates)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsText(String value, String... candidates) {
        String normalized = normalize(value);
        if (normalized == null) {
            return false;
        }
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank() && normalized.contains(normalize(candidate))) {
                return true;
            }
        }
        return false;
    }

    private boolean containsAny(String normalizedValue, String... candidates) {
        if (normalizedValue == null) {
            return false;
        }
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank() && normalizedValue.contains(candidate.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private boolean equalsAny(String value, String... candidates) {
        String normalized = normalize(value);
        if (normalized == null) {
            return false;
        }
        for (String candidate : candidates) {
            if (Objects.equals(normalized, normalize(candidate))) {
                return true;
            }
        }
        return false;
    }

    private String normalize(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return normalized.isEmpty() ? null : normalized;
    }
}
