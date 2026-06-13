package io.contexa.contexacore.verification.runtime;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import jakarta.servlet.http.HttpServletRequest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class OfficialVerificationRuntimeEvidenceSupport {

    public static final String BROWSER_OBSERVATION_ATTRIBUTE = "officialVerification.browserObservation";

    private OfficialVerificationRuntimeEvidenceSupport() {
    }

    public static NamedSource named(String name, Map<String, Object> source) {
        return new NamedSource(name, source);
    }

    public static String sourceName(Map<String, Object> selected, NamedSource... sources) {
        if (selected == null || selected.isEmpty()) {
            return "absent";
        }
        if (sources != null) {
            for (NamedSource source : sources) {
                if (source != null && source.matches(selected)) {
                    return source.name();
                }
            }
        }
        return "resolved";
    }

    public static Map<String, Object> sourceState(
            String primarySource,
            boolean primaryPresent,
            String resolvedSource,
            boolean complete,
            List<String> missingFields
    ) {
        Map<String, Object> state = new LinkedHashMap<>();
        state.put("primarySource", primarySource);
        state.put("primaryPresent", primaryPresent);
        state.put("resolvedSource", resolvedSource);
        state.put("fallbackUsed", primaryPresent ? !primarySource.equals(resolvedSource) : !"absent".equals(resolvedSource));
        state.put("complete", complete);
        state.put("missingFields", missingFields == null ? List.of() : List.copyOf(missingFields));
        return Map.copyOf(state);
    }

    public static Map<String, Object> resolvePromptTelemetry(Map<String, Object>... sources) {
        Map<String, Object> merged = new LinkedHashMap<>();
        if (sources != null) {
            for (Map<String, Object> source : sources) {
                mergePromptTelemetrySource(merged, source);
            }
        }
        return merged.isEmpty() ? Map.of() : Map.copyOf(merged);
    }

    public static boolean hasPromptTelemetry(Map<String, Object> source) {
        return hasValue(resolvePromptTelemetry(source),
                "promptKey",
                "templateKey",
                "promptTemplateKey",
                "promptVersion",
                "promptHash",
                "systemPromptHash",
                "userPromptHash",
                "promptSectionSet",
                "promptRuntimeTelemetryLinked",
                "officialVerificationPinnedModelId",
                "officialVerificationTemperature",
                "officialVerificationTopP",
                "officialVerificationSeed",
                "officialVerificationMaxTokens");
    }

    public static void storeBrowserObservation(HttpServletRequest request, Map<String, Object> browserObservation) {
        if (request == null) {
            return;
        }
        Map<String, Object> normalized = normalizeBrowserObservation(browserObservation);
        request.setAttribute(BROWSER_OBSERVATION_ATTRIBUTE, normalized.isEmpty() ? null : normalized);
    }

    public static Map<String, Object> browserObservation(HttpServletRequest request) {
        if (request == null) {
            return Map.of();
        }
        Object value = request.getAttribute(BROWSER_OBSERVATION_ATTRIBUTE);
        if (!(value instanceof Map<?, ?> raw)) {
            return Map.of();
        }
        Map<String, Object> converted = new LinkedHashMap<>();
        raw.forEach((key, item) -> {
            if (key instanceof String textKey) {
                converted.put(textKey, item);
            }
        });
        return normalizeBrowserObservation(converted);
    }

    public static Map<String, String> withBrowserObservationRequestFacts(Map<String, String> facts, HttpServletRequest request) {
        Map<String, String> mutable = facts == null ? new LinkedHashMap<>() : new LinkedHashMap<>(facts);
        putScalar(mutable, "executionMode", requestAttribute(request, "officialVerification.executionMode"));
        putScalar(mutable, "executionCondition", requestAttribute(request, "officialVerification.executionCondition"));
        putScalar(mutable, "executionConditionMultiAccount", requestAttribute(request, "officialVerification.executionConditionMultiAccount"));
        putScalar(mutable, "executionConditionRepeated", requestAttribute(request, "officialVerification.executionConditionRepeated"));
        putScalar(mutable, "subjectAccount", requestAttribute(request, "officialVerification.subjectAccount"));
        putScalar(mutable, "comparisonAccounts", requestAttribute(request, "officialVerification.comparisonAccounts"));
        putScalar(mutable, "comparisonAccountCount", requestAttribute(request, "officialVerification.comparisonAccountCount"));
        putScalar(mutable, "requestedRunCount", requestAttribute(request, "officialVerification.requestedRunCount"));
        putScalar(mutable, "requestedRequestPath", requestAttribute(request, "officialVerification.requestedRequestPath"));
        putScalar(mutable, "resolvedRequestPath", requestAttribute(request, "officialVerification.resolvedRequestPath"));
        putScalar(mutable, "llmRuntimeMode", requestAttribute(request, "officialVerification.llmRuntimeMode"));
        putScalar(mutable, "chatRuntimeProvider", requestAttribute(request, "officialVerification.chatRuntimeProvider"));
        putScalar(mutable, "embeddingRuntimeProvider", requestAttribute(request, "officialVerification.embeddingRuntimeProvider"));
        putScalar(mutable, "embeddingPriority", requestAttribute(request, "officialVerification.embeddingPriority"));
        putScalar(mutable, "embeddingDedicatedRuntimeEnabled", requestAttribute(request, "officialVerification.embeddingDedicatedRuntimeEnabled"));
        putScalar(mutable, "chatOllamaBaseUrl", requestAttribute(request, "officialVerification.chatOllamaBaseUrl"));
        putScalar(mutable, "embeddingOllamaBaseUrl", requestAttribute(request, "officialVerification.embeddingOllamaBaseUrl"));
        putScalar(mutable, "runtimeProfileCode", requestAttribute(request, "officialVerification.runtimeProfileCode"));
        putScalar(mutable, "runtimeModelId", requestAttribute(request, "officialVerification.runtimeModelId"));
        putScalar(mutable, "runtimeComparisonModels", requestAttribute(request, "officialVerification.runtimeComparisonModels"));
        putScalar(mutable, "runtimeComparisonModelCount", requestAttribute(request, "officialVerification.runtimeComparisonModelCount"));
        putScalar(mutable, "runtimeTemperature", requestAttribute(request, "officialVerification.runtimeTemperature"));
        putScalar(mutable, "runtimeTopP", requestAttribute(request, "officialVerification.runtimeTopP"));
        putScalar(mutable, "runtimeSeed", requestAttribute(request, "officialVerification.runtimeSeed"));
        putScalar(mutable, "runtimeMaxTokens", requestAttribute(request, "officialVerification.runtimeMaxTokens"));
        putScalar(mutable, "runtimeDisableRetries", requestAttribute(request, "officialVerification.runtimeDisableRetries"));
        putScalar(mutable, "runtimeDisableOllamaThinking", requestAttribute(request, "officialVerification.runtimeDisableOllamaThinking"));
        putScalar(mutable, "runtimePreflightReady", requestAttribute(request, "officialVerification.runtimePreflightReady"));
        putScalar(mutable, "runtimePreflightStatusCode", requestAttribute(request, "officialVerification.runtimePreflightStatusCode"));
        putScalar(mutable, "runtimePreflightMessage", requestAttribute(request, "officialVerification.runtimePreflightMessage"));
        putScalar(mutable, "runtimePreflightModelCount", requestAttribute(request, "officialVerification.runtimePreflightModelCount"));
        Map<String, Object> browserObservation = browserObservation(request);
        if (browserObservation.isEmpty()) {
            return Map.copyOf(mutable);
        }
        mutable.put("browserObservation", "provided");
        mutable.put("browserObservationSections", String.join(", ", browserObservation.keySet()));
        mutable.put("browserRequestEvent", browserObservation.containsKey("requestEvent") ? "provided" : "absent");
        mutable.put("browserSessionContext", browserObservation.containsKey("sessionContext") ? "provided" : "absent");
        mutable.put("browserBehaviorContext", browserObservation.containsKey("behaviorContext") ? "provided" : "absent");
        mutable.put("browserUserPrompt", browserObservation.containsKey("userPrompt") ? "provided" : "absent");
        mutable.put("browserSystemPrompt", browserObservation.containsKey("systemPrompt") ? "provided" : "absent");
        mutable.put("browserMetadata", browserObservation.containsKey("metadata") ? "provided" : "absent");
        mutable.put("browserObservedResponse", browserObservation.containsKey("browserObservedResponse") ? "provided" : "absent");
        putScalar(mutable, "browserBundleId", browserBundleId(browserObservation));
        putScalar(mutable, "browserBundleRequestId", browserObservation.get("requestId"));
        putScalar(mutable, "browserBundleCorrelationId", browserObservation.get("correlationId"));
        putScalar(mutable, "browserBundlePromptHash", browserObservation.get("promptHash"));
        putScalar(mutable, "browserBundleRunId", browserObservation.get("runId"));
        putScalar(mutable, "browserBundleCapturedAt", browserObservation.get("capturedAt"));
        return Map.copyOf(mutable);
    }

    public static Map<String, Object> withBrowserObservationRawEvidence(Map<String, Object> evidence, HttpServletRequest request) {
        Map<String, Object> mutable = evidence == null ? new LinkedHashMap<>() : new LinkedHashMap<>(evidence);
        Map<String, Object> browserObservation = browserObservation(request);
        Map<String, Object> replayPlan = requestExecutionPlan(request);
        Map<String, Object> runtimeProfile = requestRuntimeProfile(request);
        if (!browserObservation.isEmpty()) {
            mutable.put("browserObservation", browserObservation);
        }
        if (!replayPlan.isEmpty()) {
            mutable.put("officialVerificationReplayPlan", replayPlan);
        }
        if (!runtimeProfile.isEmpty()) {
            mutable.put("officialVerificationRuntimeProfile", runtimeProfile);
        }
        return Map.copyOf(mutable);
    }

    public static Map<String, String> browserObservationMetadata(HttpServletRequest request) {
        Map<String, Object> browserObservation = browserObservation(request);
        if (browserObservation.isEmpty()) {
            return Map.of();
        }
        Map<String, String> metadata = new LinkedHashMap<>();
        metadata.put("browserObservationProvided", "true");
        metadata.put("browserObservationSections", String.join(",", browserObservation.keySet()));
        metadata.put("browserObservationSectionCount", Integer.toString(browserObservation.size()));
        putScalar(metadata, "browserObservationBundleId", browserBundleId(browserObservation));
        putScalar(metadata, "browserObservationExecutionMode", requestAttribute(request, "officialVerification.executionMode"));
        putScalar(metadata, "browserObservationExecutionCondition", requestAttribute(request, "officialVerification.executionCondition"));
        putScalar(metadata, "browserObservationSubjectAccount", requestAttribute(request, "officialVerification.subjectAccount"));
        putScalar(metadata, "browserObservationComparisonAccounts", requestAttribute(request, "officialVerification.comparisonAccounts"));
        putScalar(metadata, "browserObservationRequestId", browserObservation.get("requestId"));
        putScalar(metadata, "browserObservationCorrelationId", browserObservation.get("correlationId"));
        putScalar(metadata, "browserObservationPromptHash", browserObservation.get("promptHash"));
        putScalar(metadata, "browserObservationRunId", browserObservation.get("runId"));
        putScalar(metadata, "browserObservationCapturedAt", browserObservation.get("capturedAt"));
        putScalar(metadata, "browserObservationLlmRuntimeMode", requestAttribute(request, "officialVerification.llmRuntimeMode"));
        putScalar(metadata, "browserObservationChatRuntimeProvider", requestAttribute(request, "officialVerification.chatRuntimeProvider"));
        putScalar(metadata, "browserObservationEmbeddingRuntimeProvider", requestAttribute(request, "officialVerification.embeddingRuntimeProvider"));
        putScalar(metadata, "browserObservationEmbeddingDedicatedRuntimeEnabled", requestAttribute(request, "officialVerification.embeddingDedicatedRuntimeEnabled"));
        return Map.copyOf(metadata);
    }

    private static Map<String, Object> requestExecutionPlan(HttpServletRequest request) {
        Map<String, Object> replayPlan = new LinkedHashMap<>();
        putScalarObject(replayPlan, "executionMode", requestAttribute(request, "officialVerification.executionMode"));
        putScalarObject(replayPlan, "executionCondition", requestAttribute(request, "officialVerification.executionCondition"));
        putScalarObject(replayPlan, "executionConditionMultiAccount", requestAttribute(request, "officialVerification.executionConditionMultiAccount"));
        putScalarObject(replayPlan, "executionConditionRepeated", requestAttribute(request, "officialVerification.executionConditionRepeated"));
        putScalarObject(replayPlan, "subjectAccount", requestAttribute(request, "officialVerification.subjectAccount"));
        putScalarObject(replayPlan, "comparisonAccounts", requestAttribute(request, "officialVerification.comparisonAccounts"));
        putScalarObject(replayPlan, "comparisonAccountCount", requestAttribute(request, "officialVerification.comparisonAccountCount"));
        putScalarObject(replayPlan, "requestedRunCount", requestAttribute(request, "officialVerification.requestedRunCount"));
        putScalarObject(replayPlan, "requestedRequestPath", requestAttribute(request, "officialVerification.requestedRequestPath"));
        putScalarObject(replayPlan, "resolvedRequestPath", requestAttribute(request, "officialVerification.resolvedRequestPath"));
        putScalarObject(replayPlan, "llmRuntimeMode", requestAttribute(request, "officialVerification.llmRuntimeMode"));
        putScalarObject(replayPlan, "chatRuntimeProvider", requestAttribute(request, "officialVerification.chatRuntimeProvider"));
        putScalarObject(replayPlan, "embeddingRuntimeProvider", requestAttribute(request, "officialVerification.embeddingRuntimeProvider"));
        putScalarObject(replayPlan, "embeddingPriority", requestAttribute(request, "officialVerification.embeddingPriority"));
        putScalarObject(replayPlan, "embeddingDedicatedRuntimeEnabled", requestAttribute(request, "officialVerification.embeddingDedicatedRuntimeEnabled"));
        putScalarObject(replayPlan, "chatOllamaBaseUrl", requestAttribute(request, "officialVerification.chatOllamaBaseUrl"));
        putScalarObject(replayPlan, "embeddingOllamaBaseUrl", requestAttribute(request, "officialVerification.embeddingOllamaBaseUrl"));
        putScalarObject(replayPlan, "runtimeProfileCode", requestAttribute(request, "officialVerification.runtimeProfileCode"));
        putScalarObject(replayPlan, "runtimeModelId", requestAttribute(request, "officialVerification.runtimeModelId"));
        putScalarObject(replayPlan, "runtimeComparisonModels", requestAttribute(request, "officialVerification.runtimeComparisonModels"));
        putScalarObject(replayPlan, "runtimeComparisonModelCount", requestAttribute(request, "officialVerification.runtimeComparisonModelCount"));
        putScalarObject(replayPlan, "runtimeTemperature", requestAttribute(request, "officialVerification.runtimeTemperature"));
        putScalarObject(replayPlan, "runtimeTopP", requestAttribute(request, "officialVerification.runtimeTopP"));
        putScalarObject(replayPlan, "runtimeSeed", requestAttribute(request, "officialVerification.runtimeSeed"));
        putScalarObject(replayPlan, "runtimeMaxTokens", requestAttribute(request, "officialVerification.runtimeMaxTokens"));
        putScalarObject(replayPlan, "runtimeDisableRetries", requestAttribute(request, "officialVerification.runtimeDisableRetries"));
        putScalarObject(replayPlan, "runtimeDisableOllamaThinking", requestAttribute(request, "officialVerification.runtimeDisableOllamaThinking"));
        putScalarObject(replayPlan, "runtimePreflightReady", requestAttribute(request, "officialVerification.runtimePreflightReady"));
        putScalarObject(replayPlan, "runtimePreflightStatusCode", requestAttribute(request, "officialVerification.runtimePreflightStatusCode"));
        putScalarObject(replayPlan, "runtimePreflightMessage", requestAttribute(request, "officialVerification.runtimePreflightMessage"));
        putScalarObject(replayPlan, "runtimePreflightModelCount", requestAttribute(request, "officialVerification.runtimePreflightModelCount"));
        return replayPlan.isEmpty() ? Map.of() : Map.copyOf(replayPlan);
    }

    private static Map<String, Object> requestRuntimeProfile(HttpServletRequest request) {
        Map<String, Object> runtimeProfile = new LinkedHashMap<>();
        putScalarObject(runtimeProfile, "llmRuntimeMode", requestAttribute(request, "officialVerification.llmRuntimeMode"));
        putScalarObject(runtimeProfile, "chatRuntimeProvider", requestAttribute(request, "officialVerification.chatRuntimeProvider"));
        putScalarObject(runtimeProfile, "embeddingRuntimeProvider", requestAttribute(request, "officialVerification.embeddingRuntimeProvider"));
        putScalarObject(runtimeProfile, "embeddingPriority", requestAttribute(request, "officialVerification.embeddingPriority"));
        putScalarObject(runtimeProfile, "embeddingDedicatedRuntimeEnabled", requestAttribute(request, "officialVerification.embeddingDedicatedRuntimeEnabled"));
        putScalarObject(runtimeProfile, "chatOllamaBaseUrl", requestAttribute(request, "officialVerification.chatOllamaBaseUrl"));
        putScalarObject(runtimeProfile, "embeddingOllamaBaseUrl", requestAttribute(request, "officialVerification.embeddingOllamaBaseUrl"));
        putScalarObject(runtimeProfile, "runtimeProfileCode", requestAttribute(request, "officialVerification.runtimeProfileCode"));
        putScalarObject(runtimeProfile, "runtimeModelId", requestAttribute(request, "officialVerification.runtimeModelId"));
        putScalarObject(runtimeProfile, "runtimeComparisonModels", requestAttribute(request, "officialVerification.runtimeComparisonModels"));
        putScalarObject(runtimeProfile, "runtimeComparisonModelCount", requestAttribute(request, "officialVerification.runtimeComparisonModelCount"));
        putScalarObject(runtimeProfile, "runtimeTemperature", requestAttribute(request, "officialVerification.runtimeTemperature"));
        putScalarObject(runtimeProfile, "runtimeTopP", requestAttribute(request, "officialVerification.runtimeTopP"));
        putScalarObject(runtimeProfile, "runtimeSeed", requestAttribute(request, "officialVerification.runtimeSeed"));
        putScalarObject(runtimeProfile, "runtimeMaxTokens", requestAttribute(request, "officialVerification.runtimeMaxTokens"));
        putScalarObject(runtimeProfile, "runtimeDisableRetries", requestAttribute(request, "officialVerification.runtimeDisableRetries"));
        putScalarObject(runtimeProfile, "runtimeDisableOllamaThinking", requestAttribute(request, "officialVerification.runtimeDisableOllamaThinking"));
        putScalarObject(runtimeProfile, "runtimePreflightReady", requestAttribute(request, "officialVerification.runtimePreflightReady"));
        putScalarObject(runtimeProfile, "runtimePreflightStatusCode", requestAttribute(request, "officialVerification.runtimePreflightStatusCode"));
        putScalarObject(runtimeProfile, "runtimePreflightMessage", requestAttribute(request, "officialVerification.runtimePreflightMessage"));
        putScalarObject(runtimeProfile, "runtimePreflightModelCount", requestAttribute(request, "officialVerification.runtimePreflightModelCount"));
        return runtimeProfile.isEmpty() ? Map.of() : Map.copyOf(runtimeProfile);
    }

    private static String browserBundleId(Map<String, Object> browserObservation) {
        if (browserObservation == null || browserObservation.isEmpty()) {
            return null;
        }
        return firstNonBlank(
                normalizeScalarValue(browserObservation.get("runId")),
                normalizeScalarValue(browserObservation.get("requestId")),
                normalizeScalarValue(browserObservation.get("correlationId")),
                normalizeScalarValue(browserObservation.get("promptHash")),
                normalizeScalarValue(browserObservation.get("capturedAt"))
        );
    }

    private static String requestAttribute(HttpServletRequest request, String attributeName) {
        if (request == null || attributeName == null || attributeName.isBlank()) {
            return null;
        }
        Object value = request.getAttribute(attributeName);
        return normalizeScalarValue(value);
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private static Map<String, Object> normalizeBrowserObservation(Map<String, Object> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> normalized = new LinkedHashMap<>();
        normalizeSection(normalized, "requestEvent", source.get("requestEvent"));
        normalizeSection(normalized, "sessionContext", source.get("sessionContext"));
        normalizeSection(normalized, "behaviorContext", source.get("behaviorContext"));
        normalizeSection(normalized, "userPrompt", source.get("userPrompt"));
        normalizeSection(normalized, "systemPrompt", source.get("systemPrompt"));
        normalizeSection(normalized, "metadata", source.get("metadata"));
        normalizeSection(normalized, "browserObservedResponse", source.get("browserObservedResponse"));
        normalizeScalar(normalized, "requestId", source.get("requestId"));
        normalizeScalar(normalized, "correlationId", source.get("correlationId"));
        normalizeScalar(normalized, "promptHash", source.get("promptHash"));
        normalizeScalar(normalized, "runId", source.get("runId"));
        normalizeScalar(normalized, "capturedAt", source.get("capturedAt"));
        return normalized.isEmpty() ? Map.of() : Map.copyOf(normalized);
    }

    private static void normalizeSection(Map<String, Object> target, String key, Object value) {
        Object normalized = normalizeValue(value);
        if (normalized != null) {
            target.put(key, normalized);
        }
    }

    private static void normalizeScalar(Map<String, Object> target, String key, Object value) {
        Object normalized = normalizeValue(value);
        if (normalized != null) {
            target.put(key, normalized);
        }
    }

    private static void putScalar(Map<String, String> target, String key, Object value) {
        String text = normalizeScalarValue(value);
        if (text != null) {
            target.put(key, text);
        }
    }

    private static void putScalarObject(Map<String, Object> target, String key, Object value) {
        String text = normalizeScalarValue(value);
        if (text != null) {
            target.put(key, text);
        }
    }

    private static String normalizeScalarValue(Object value) {
        Object normalized = normalizeValue(value);
        return normalized == null ? null : String.valueOf(normalized);
    }

    private static Object normalizeValue(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof CharSequence text) {
            String normalized = text.toString().trim();
            return normalized.isBlank() ? null : normalized;
        }
        if (value instanceof Map<?, ?> rawMap) {
            Map<String, Object> normalized = new LinkedHashMap<>();
            rawMap.forEach((key, item) -> {
                if (key instanceof String textKey) {
                    Object nested = normalizeValue(item);
                    if (nested != null) {
                        normalized.put(textKey, nested);
                    }
                }
            });
            return normalized.isEmpty() ? null : Map.copyOf(normalized);
        }
        if (value instanceof List<?> rawList) {
            List<Object> normalized = new ArrayList<>();
            for (Object item : rawList) {
                Object nested = normalizeValue(item);
                if (nested != null) {
                    normalized.add(nested);
                }
            }
            return normalized.isEmpty() ? null : List.copyOf(normalized);
        }
        if (value instanceof Number || value instanceof Boolean) {
            return value;
        }
        String normalized = String.valueOf(value).trim();
        return normalized.isBlank() ? null : normalized;
    }

    private static void mergePromptTelemetrySource(Map<String, Object> target, Map<String, Object> source) {
        if (source == null || source.isEmpty()) {
            return;
        }
        source.forEach((key, value) -> {
            if (key != null && value != null) {
                target.putIfAbsent(key, value);
            }
        });
        mergeNestedTelemetry(target, source.get("promptRuntimeTelemetry"));
        mergeNestedTelemetry(target, source.get("attributes"));
    }

    private static void mergeNestedTelemetry(Map<String, Object> target, Object candidate) {
        if (!(candidate instanceof Map<?, ?> nested)) {
            return;
        }
        nested.forEach((key, value) -> {
            if (key instanceof String textKey && value != null) {
                target.putIfAbsent(textKey, value);
            }
        });
    }

    public static boolean hasValue(Map<String, Object> source, String... keys) {
        if (source == null || source.isEmpty() || keys == null) {
            return false;
        }
        for (String key : keys) {
            Object value = source.get(key);
            if (value == null) {
                continue;
            }
            if (value instanceof CharSequence text) {
                if (!text.toString().trim().isBlank()) {
                    return true;
                }
                continue;
            }
            if (value instanceof List<?> items) {
                if (!items.isEmpty()) {
                    return true;
                }
                continue;
            }
            return true;
        }
        return false;
    }

    public static Map<String, Object> decisionOutboxSnapshot(
            SecurityDecisionForwardingOutboxRecord record,
            Map<String, Object> payload
    ) {
        if (record == null) {
            return Map.of();
        }
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("status", record.getStatus());
        snapshot.put("attemptCount", record.getAttemptCount());
        snapshot.put("correlationId", record.getCorrelationId());
        snapshot.put("createdAt", record.getCreatedAt());
        snapshot.put("deliveredAt", record.getDeliveredAt());
        snapshot.put("payload", payload != null ? payload : Map.of());
        return snapshot;
    }

    public static Map<String, Object> promptAuditOutboxSnapshot(
            PromptContextAuditForwardingOutboxRecord record,
            Map<String, Object> payload
    ) {
        if (record == null) {
            return Map.of();
        }
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("auditId", record.getAuditId());
        snapshot.put("status", record.getStatus());
        snapshot.put("attemptCount", record.getAttemptCount());
        snapshot.put("correlationId", record.getCorrelationId());
        snapshot.put("createdAt", record.getCreatedAt());
        snapshot.put("deliveredAt", record.getDeliveredAt());
        snapshot.put("payload", payload != null ? payload : Map.of());
        return snapshot;
    }

    public record NamedSource(String name, Map<String, Object> source) {

        private boolean matches(Map<String, Object> selected) {
            return source != null && !source.isEmpty() && source == selected;
        }
    }
}
