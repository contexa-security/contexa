package io.contexa.contexacore.autonomous.saas.learning.calibration;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Resolves conservative scenario classes from correlated calibration observations.
 */
public class DefaultScenarioClassResolver implements ScenarioClassResolver {

    static final String NEW_DEVICE_POST_MFA_SENSITIVE = "NEW_DEVICE_POST_MFA_SENSITIVE";
    static final String LOW_DIVERSITY_EXPORT_APPROACH = "LOW_DIVERSITY_EXPORT_APPROACH";
    static final String SESSION_PATH_SIMILARITY_BREAK = "SESSION_PATH_SIMILARITY_BREAK";

    @Override
    public ScenarioClassResolution resolve(CalibrationLearningObservation observation) {
        if (observation == null) {
            return ScenarioClassResolution.unresolved();
        }

        ScenarioClassResolution hinted = resolveExplicitHint(observation);
        if (hinted.isResolved()) {
            return hinted;
        }
        if (isNewDevicePostMfaSensitive(observation)) {
            return resolved(NEW_DEVICE_POST_MFA_SENSITIVE,
                    "New-device access moved through MFA into a sensitive or administrative surface.",
                    "The correlated observation preserved post-authentication risk signals with sensitive-surface evidence.");
        }
        if (isLowDiversityExportApproach(observation)) {
            return resolved(LOW_DIVERSITY_EXPORT_APPROACH,
                    "The session collapsed onto an export-oriented privileged surface with low request diversity.",
                    "Prompt or telemetry evidence indicates a narrow export/download approach pattern.");
        }
        if (isSessionPathSimilarityBreak(observation)) {
            return resolved(SESSION_PATH_SIMILARITY_BREAK,
                    "Session-path behavior diverged from the expected access sequence.",
                    "Prompt evidence or path-jump signals indicate a similarity break before the final outcome.");
        }
        return ScenarioClassResolution.unresolved();
    }

    private ScenarioClassResolution resolveExplicitHint(CalibrationLearningObservation observation) {
        String explicit = normalize(signalText(observation, "scenarioClass"));
        if (explicit == null) {
            explicit = normalize(signalText(observation, "scenario"));
        }
        if (Objects.equals(explicit, normalize(NEW_DEVICE_POST_MFA_SENSITIVE))) {
            return resolved(NEW_DEVICE_POST_MFA_SENSITIVE, "Scenario hint matched the fixed calibration class.");
        }
        if (Objects.equals(explicit, normalize(LOW_DIVERSITY_EXPORT_APPROACH))) {
            return resolved(LOW_DIVERSITY_EXPORT_APPROACH, "Scenario hint matched the fixed calibration class.");
        }
        if (Objects.equals(explicit, normalize(SESSION_PATH_SIMILARITY_BREAK))) {
            return resolved(SESSION_PATH_SIMILARITY_BREAK, "Scenario hint matched the fixed calibration class.");
        }
        return ScenarioClassResolution.unresolved();
    }

    private boolean isNewDevicePostMfaSensitive(CalibrationLearningObservation observation) {
        return truthy(signal(observation, "isNewDevice"))
                && isSensitiveOrAdministrativeSurface(observation)
                && (truthy(signal(observation, "mfaVerified"))
                || containsText(signalText(observation, "reasonCategory"), "mfa")
                || containsAnyEvidence(observation, "mfa", "post-mfa", "multi-factor"));
    }

    private boolean isLowDiversityExportApproach(CalibrationLearningObservation observation) {
        boolean exportSurface = containsText(signalText(observation, "requestPath"), "/export", "/download", "/report")
                || equalsAny(signalText(observation, "pathCategory"), "sensitive_data", "administration")
                || containsAnyToken(observation.signalKeys(), "export", "download", "report_export");
        boolean lowDiversity = lowDiversityHint(observation)
                || observation.signalKeys().size() <= 1
                || containsAnyEvidence(observation, "low diversity", "narrow path", "single surface");
        return exportSurface && lowDiversity;
    }

    private boolean isSessionPathSimilarityBreak(CalibrationLearningObservation observation) {
        boolean explicitSignal = containsAnyToken(observation.signalKeys(),
                "session_path_similarity_break",
                "path_sequence_divergence",
                "session_entropy_collapse",
                "path_jump")
                || containsAnyEvidence(observation, "similarity break", "path divergence", "path jump", "sequence break");
        boolean promptOrTelemetryContext = observation.promptAuditLinked()
                || observation.telemetryLinked()
                || observation.deniedContextCount() > 0;
        return explicitSignal && promptOrTelemetryContext;
    }

    private boolean lowDiversityHint(CalibrationLearningObservation observation) {
        Object value = signal(observation, "lowDiversity");
        if (truthy(value)) {
            return true;
        }
        Object score = signal(observation, "requestDiversityScore");
        if (score instanceof Number number) {
            return number.doubleValue() <= 0.20d;
        }
        if (score instanceof String text) {
            try {
                return Double.parseDouble(text.trim()) <= 0.20d;
            } catch (NumberFormatException ignored) {
                return false;
            }
        }
        return false;
    }

    private boolean isSensitiveOrAdministrativeSurface(CalibrationLearningObservation observation) {
        return containsText(signalText(observation, "requestPath"), "/admin/", "/export", "/download", "/billing", "/report")
                || equalsAny(signalText(observation, "pathCategory"), "sensitive_data", "administration", "credential_management");
    }

    private ScenarioClassResolution resolved(String scenarioClass, String... facts) {
        Set<String> merged = new LinkedHashSet<>();
        for (String fact : facts) {
            if (fact != null && !fact.isBlank()) {
                merged.add(fact);
            }
        }
        return new ScenarioClassResolution(scenarioClass, List.copyOf(merged));
    }

    private Object signal(CalibrationLearningObservation observation, String key) {
        Map<String, Object> signals = observation.scenarioSignals();
        return signals != null ? signals.get(key) : null;
    }

    private String signalText(CalibrationLearningObservation observation, String key) {
        Object value = signal(observation, key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
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

    private boolean containsAnyEvidence(CalibrationLearningObservation observation, String... candidates) {
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
