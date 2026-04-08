package io.contexa.contexacore.autonomous.tiered.service.calibration;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationLearningObservation;
import io.contexa.contexacore.autonomous.saas.threat.ThreatSignalNormalizationService;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Builds runtime observations for post-decision calibration without mutating prompt inputs.
 */
public class CalibrationRuntimeObservationFactory {

    private final ThreatSignalNormalizationService threatSignalNormalizationService;

    public CalibrationRuntimeObservationFactory(ThreatSignalNormalizationService threatSignalNormalizationService) {
        this.threatSignalNormalizationService = Objects.requireNonNull(
                threatSignalNormalizationService,
                "threatSignalNormalizationService is required");
    }

    public CalibrationLearningObservation create(
            SecurityEvent event,
            SecurityDecision decision,
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis) {
        Map<String, Object> metadata = event != null && event.getMetadata() != null ? event.getMetadata() : Map.of();
        String requestPath = firstNonBlank(
                extractText(metadata, "requestPath"),
                extractText(metadata, "requestUri"),
                extractText(metadata, "fullPath"),
                extractText(metadata, "targetResource"));
        String pathCategory = resolvePathCategory(requestPath, extractBoolean(metadata, "isSensitiveResource"));
        boolean promptAuditLinked = isPromptAuditLinked(metadata);
        boolean telemetryLinked = isTelemetryLinked(metadata);
        int deniedContextCount = resolveDeniedContextCount(metadata);
        boolean newDevice = firstTrue(extractBooleanObject(metadata, "isNewDevice"),
                behaviorAnalysis != null ? behaviorAnalysis.getIsNewDevice() : null);
        boolean sensitiveSurface = isSensitiveSurface(pathCategory) || extractBoolean(metadata, "isSensitiveResource");
        boolean mfaVerified = extractBoolean(metadata, "mfaVerified");
        boolean lowDiversity = resolveLowDiversity(metadata, requestPath);
        String previousPath = firstNonBlank(
                behaviorAnalysis != null ? behaviorAnalysis.getPreviousPath() : null,
                extractText(metadata, "previousPath"));
        Long lastRequestIntervalMs = firstNonNull(
                behaviorAnalysis != null ? behaviorAnalysis.getLastRequestIntervalMs() : null,
                extractLong(metadata, "lastRequestIntervalMs"));

        LinkedHashSet<String> signalKeys = new LinkedHashSet<>();
        addStringValues(signalKeys, metadata.get("threatKnowledgeSignalKeys"));
        addStringValues(signalKeys, metadata.get("threatKnowledgeKeys"));
        addStringValues(signalKeys, metadata.get("parameterRiskFlags"));
        addStringValues(signalKeys, metadata.get("promptRiskFlags"));
        if (newDevice) {
            signalKeys.add("new_device");
        }
        if (mfaVerified) {
            signalKeys.add("mfa_verified");
        }
        if (extractBoolean(metadata, "isImpossibleTravel")) {
            signalKeys.add("impossible_travel");
        }
        if (sensitiveSurface) {
            signalKeys.add("sensitive_surface");
        }
        if (hasPathJump(previousPath, requestPath)) {
            signalKeys.add("path_jump");
            signalKeys.add("path_sequence_divergence");
        }
        if (lowDiversity) {
            signalKeys.add("low_diversity_export_approach");
        }

        Map<String, Object> scenarioSignals = new LinkedHashMap<>();
        putIfPresent(scenarioSignals, "requestPath", requestPath);
        putIfPresent(scenarioSignals, "pathCategory", pathCategory);
        putIfPresent(scenarioSignals, "previousPath", previousPath);
        putIfPresent(scenarioSignals, "reasonCategory", firstNonBlank(
                extractText(metadata, "reasonCategory"),
                extractText(metadata, "operatorReasonCategory"),
                decision != null ? decision.getThreatCategory() : null));
        putIfPresent(scenarioSignals, "isNewDevice", newDevice);
        putIfPresent(scenarioSignals, "mfaVerified", mfaVerified);
        putIfPresent(scenarioSignals, "isSensitiveResource", sensitiveSurface);
        putIfPresent(scenarioSignals, "requestDiversityScore", extractDoubleObject(metadata, "requestDiversityScore"));
        putIfPresent(scenarioSignals, "lowDiversity", lowDiversity);
        putIfPresent(scenarioSignals, "failedLoginAttempts", resolveFailedLoginAttempts(metadata));
        putIfPresent(scenarioSignals, "promptAuditLinked", promptAuditLinked);
        putIfPresent(scenarioSignals, "telemetryLinked", telemetryLinked);
        putIfPresent(scenarioSignals, "deniedDocumentCount", deniedContextCount);
        putIfPresent(scenarioSignals, "lastRequestIntervalMs", lastRequestIntervalMs);
        putIfPresent(scenarioSignals, "contextBindingHashMismatch", firstTrue(
                behaviorAnalysis != null ? behaviorAnalysis.getContextBindingHashMismatch() : null,
                extractBooleanObject(metadata, "contextBindingHashMismatch")));
        putIfPresent(scenarioSignals, "aiAnalysisLevel", decision != null ? decision.getProcessingLayer() : null);

        List<String> evidenceFacts = buildEvidenceFacts(
                requestPath,
                pathCategory,
                previousPath,
                lastRequestIntervalMs,
                promptAuditLinked,
                telemetryLinked,
                deniedContextCount,
                newDevice,
                mfaVerified,
                sensitiveSurface,
                lowDiversity,
                metadata,
                signalKeys);

        return new CalibrationLearningObservation(
                resolveCorrelationId(event, metadata),
                decision != null && decision.getAction() != null ? decision.getAction().name() : null,
                decision != null && decision.resolveAutonomousAction() != null ? decision.resolveAutonomousAction().name() : null,
                null,
                null,
                null,
                null,
                resolveDecisionConfidence(decision),
                decision != null && decision.getProcessingLayer() > 0 ? decision.getProcessingLayer() : null,
                promptAuditLinked,
                deniedContextCount,
                telemetryLinked,
                List.copyOf(signalKeys),
                scenarioSignals.isEmpty() ? Map.of() : Map.copyOf(scenarioSignals),
                evidenceFacts);
    }

    private List<String> buildEvidenceFacts(
            String requestPath,
            String pathCategory,
            String previousPath,
            Long lastRequestIntervalMs,
            boolean promptAuditLinked,
            boolean telemetryLinked,
            int deniedContextCount,
            boolean newDevice,
            boolean mfaVerified,
            boolean sensitiveSurface,
            boolean lowDiversity,
            Map<String, Object> metadata,
            LinkedHashSet<String> signalKeys) {
        LinkedHashSet<String> facts = new LinkedHashSet<>();
        if (StringUtils.hasText(requestPath)) {
            facts.add(String.format(Locale.ROOT,
                    "Runtime request path %s maps to surface %s.",
                    requestPath,
                    pathCategory));
        }
        if (newDevice) {
            facts.add("Runtime decision retained a new-device signal.");
        }
        if (extractBoolean(metadata, "isImpossibleTravel")) {
            facts.add("Runtime decision retained an impossible-travel signal.");
        }
        if (mfaVerified && sensitiveSurface) {
            facts.add("Post-MFA access moved into a sensitive or administrative surface.");
        }
        if (hasPathJump(previousPath, requestPath)) {
            facts.add(String.format(Locale.ROOT,
                    "Detected path jump from %s to %s.",
                    previousPath,
                    requestPath));
        }
        if (lastRequestIntervalMs != null && lastRequestIntervalMs > 0L) {
            facts.add(String.format(Locale.ROOT,
                    "Last request interval was %dms.",
                    lastRequestIntervalMs));
        }
        if (promptAuditLinked) {
            facts.add("Prompt audit lineage was linked to the runtime decision.");
        }
        if (telemetryLinked) {
            facts.add("Prompt runtime telemetry was linked to the runtime decision.");
        }
        if (deniedContextCount > 0) {
            facts.add(String.format(Locale.ROOT,
                    "Prompt authorization denied %d contexts during retrieval.",
                    deniedContextCount));
        }
        if (lowDiversity) {
            facts.add("Detected low diversity export approach in the runtime request context.");
        }
        if (!signalKeys.isEmpty()) {
            facts.add("Calibration signal keys: " + String.join(", ", signalKeys));
        }
        return List.copyOf(facts);
    }

    private String resolvePathCategory(String requestPath, boolean sensitiveResource) {
        String category = threatSignalNormalizationService.classifyTargetSurface(requestPath);
        if ("application".equals(category) && sensitiveResource) {
            return "sensitive_data";
        }
        return category;
    }

    private boolean isPromptAuditLinked(Map<String, Object> metadata) {
        if (extractBoolean(metadata, "promptRuntimeTelemetryLinked")) {
            return true;
        }
        return StringUtils.hasText(extractText(metadata, "promptHash"))
                || StringUtils.hasText(extractText(metadata, "systemPromptHash"))
                || StringUtils.hasText(extractText(metadata, "userPromptHash"))
                || resolveDeniedContextCount(metadata) > 0;
    }

    private boolean isTelemetryLinked(Map<String, Object> metadata) {
        return extractBoolean(metadata, "promptRuntimeTelemetryLinked")
                || !PromptRuntimeTelemetrySupport.extractRuntimeTelemetry(metadata).isEmpty();
    }

    private int resolveDeniedContextCount(Map<String, Object> metadata) {
        Integer value = firstNonNull(
                extractInteger(metadata, "deniedDocumentCount"),
                extractInteger(metadata, "documentsDenied"),
                extractInteger(metadata, "promptDeniedDocumentCount"));
        return value != null ? value : 0;
    }

    private Integer resolveFailedLoginAttempts(Map<String, Object> metadata) {
        return firstNonNull(
                extractInteger(metadata, "failedLoginAttempts"),
                extractInteger(metadata, "auth.failure_count"));
    }

    private boolean resolveLowDiversity(Map<String, Object> metadata, String requestPath) {
        Boolean explicit = extractBooleanObject(metadata, "lowDiversity");
        if (explicit != null) {
            return explicit;
        }
        Double diversityScore = extractDoubleObject(metadata, "requestDiversityScore");
        if (diversityScore != null) {
            return diversityScore <= 0.20d;
        }
        Integer recentRequestCount = extractInteger(metadata, "recentRequestCount");
        return recentRequestCount != null
                && recentRequestCount <= 2
                && isSensitiveSurface(threatSignalNormalizationService.classifyTargetSurface(requestPath));
    }

    private boolean hasPathJump(String previousPath, String requestPath) {
        return StringUtils.hasText(previousPath)
                && StringUtils.hasText(requestPath)
                && !previousPath.trim().equalsIgnoreCase(requestPath.trim());
    }

    private boolean isSensitiveSurface(String pathCategory) {
        if (!StringUtils.hasText(pathCategory)) {
            return false;
        }
        String normalized = pathCategory.trim().toLowerCase(Locale.ROOT);
        return "administration".equals(normalized)
                || "sensitive_data".equals(normalized)
                || "credential_management".equals(normalized);
    }

    private String resolveCorrelationId(SecurityEvent event, Map<String, Object> metadata) {
        return firstNonBlank(
                extractText(metadata, "correlationId"),
                extractText(metadata, "requestId"),
                event != null ? event.getEventId() : null);
    }

    private Double resolveDecisionConfidence(SecurityDecision decision) {
        if (decision == null) {
            return null;
        }
        return firstNonNull(decision.getConfidence(), decision.resolveAuditConfidence());
    }

    private void addStringValues(LinkedHashSet<String> target, Object value) {
        if (value instanceof List<?> list) {
            for (Object item : list) {
                if (item != null && StringUtils.hasText(String.valueOf(item))) {
                    target.add(normalizeToken(String.valueOf(item)));
                }
            }
            return;
        }
        if (value != null && StringUtils.hasText(String.valueOf(value))) {
            target.add(normalizeToken(String.valueOf(value)));
        }
    }

    private String normalizeToken(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "_")
                .replaceAll("_+", "_")
                .replaceAll("^_", "")
                .replaceAll("_$", "");
        return normalized.isBlank() ? null : normalized;
    }

    private void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    private String extractText(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isBlank() ? null : text;
    }

    private Integer extractInteger(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            try {
                return Integer.parseInt(text.trim());
            }
            catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private Long extractLong(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            try {
                return Long.parseLong(text.trim());
            }
            catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private Double extractDoubleObject(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            try {
                return Double.parseDouble(text.trim());
            }
            catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private Boolean extractBooleanObject(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            return Boolean.parseBoolean(text.trim());
        }
        return null;
    }

    private boolean extractBoolean(Map<String, Object> source, String key) {
        return Boolean.TRUE.equals(extractBooleanObject(source, key));
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    @SafeVarargs
    private final <T> T firstNonNull(T... values) {
        if (values == null) {
            return null;
        }
        for (T value : values) {
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private boolean firstTrue(Boolean... values) {
        if (values == null) {
            return false;
        }
        for (Boolean value : values) {
            if (Boolean.TRUE.equals(value)) {
                return true;
            }
        }
        return false;
    }
}