package io.contexa.contexacore.verification.runtime;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;

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

    public static OfficialVerificationExecutionRequest storeBrowserObservation(
            OfficialVerificationExecutionRequest request,
            Map<String, Object> browserObservation
    ) {
        return OfficialVerificationBrowserObservationSupport.storeBrowserObservation(request, browserObservation);
    }

    public static Map<String, Object> browserObservation(OfficialVerificationExecutionRequest request) {
        return OfficialVerificationBrowserObservationSupport.browserObservation(request);
    }

    public static Map<String, String> withBrowserObservationRequestFacts(
            Map<String, String> facts,
            OfficialVerificationExecutionRequest request
    ) {
        return OfficialVerificationBrowserObservationSupport.withBrowserObservationRequestFacts(facts, request);
    }

    public static Map<String, Object> withBrowserObservationRawEvidence(
            Map<String, Object> evidence,
            OfficialVerificationExecutionRequest request
    ) {
        return OfficialVerificationBrowserObservationSupport.withBrowserObservationRawEvidence(evidence, request);
    }

    public static Map<String, String> browserObservationMetadata(OfficialVerificationExecutionRequest request) {
        return OfficialVerificationBrowserObservationSupport.browserObservationMetadata(request);
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
