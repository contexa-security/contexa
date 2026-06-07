package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

final class PromptQualityFaultInjector {

    static final String SCENARIO_CCSR_RESOURCE_ACTION_NA = "CCSR_RESOURCE_ACTION_NA";
    static final String SCENARIO_RAG_SCOPE_SLOT_FAULT = "RAG_SCOPE_SLOT_FAULT";
    static final String SCENARIO_12_METRIC_RUNTIME_SLOT_FAULTS = "12_METRIC_RUNTIME_SLOT_FAULTS";
    static final String SCENARIO_ALL_12_RUNTIME_SLOT_FAULTS = "ALL_12_RUNTIME_SLOT_FAULTS";

    private PromptQualityFaultInjector() {
    }

    static PromptQualityFaultInjectionResult apply(String userPrompt, SecurityPromptBuildContext buildContext) {
        String scenario = resolveScenario(buildContext);
        if (scenario == null || userPrompt == null || userPrompt.isBlank()) {
            return new PromptQualityFaultInjectionResult(userPrompt, Map.of());
        }

        String modifiedPrompt = switch (scenario) {
            case SCENARIO_CCSR_RESOURCE_ACTION_NA -> injectResourceActionConflict(userPrompt);
            case SCENARIO_RAG_SCOPE_SLOT_FAULT -> injectRagScopeSlotFault(userPrompt);
            case SCENARIO_12_METRIC_RUNTIME_SLOT_FAULTS,
                 SCENARIO_ALL_12_RUNTIME_SLOT_FAULTS -> injectAllMetricRuntimeSlotFaults(userPrompt);
            default -> userPrompt;
        };
        if (modifiedPrompt.equals(userPrompt)) {
            return new PromptQualityFaultInjectionResult(userPrompt, Map.of());
        }

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("pqaPromptFaultApplied", true);
        metadata.put("pqaPromptFaultScenario", scenario);
        metadata.put("pqaPromptFaultTarget", faultTarget(scenario));
        SecurityEvent event = buildContext != null ? buildContext.getEvent() : null;
        if (event != null) {
            metadata.forEach(event::addMetadata);
        }
        return new PromptQualityFaultInjectionResult(modifiedPrompt, metadata);
    }

    private static String resolveScenario(SecurityPromptBuildContext buildContext) {
        SecurityEvent event = buildContext != null ? buildContext.getEvent() : null;
        Map<String, Object> metadata = event != null ? event.getMetadata() : null;
        if (metadata == null || metadata.isEmpty()) {
            return null;
        }
        Object enabled = metadata.get("pqaPromptFaultEnabled");
        if (!(enabled instanceof Boolean enabledFlag) || !enabledFlag) {
            return null;
        }
        Object rawScenario = metadata.get("pqaPromptFaultScenario");
        if (rawScenario == null) {
            return null;
        }
        String scenario = String.valueOf(rawScenario).trim();
        if (scenario.isBlank()) {
            return null;
        }
        return scenario.toUpperCase(Locale.ROOT).replace('-', '_');
    }

    private static String injectResourceActionConflict(String userPrompt) {
        String result = userPrompt;
        result = replaceLineValue(result, "ResourceId", "N/A");
        result = replaceLineValue(result, "RequestPath", "N/A");
        result = replaceLineValue(result, "HttpMethod", "N/A");
        result = replaceLineValue(result, "ActionFamily", "N/A");
        result = replaceLineValue(result, "ResourceType", "N/A");
        result = replaceLineValue(result, "BusinessLabel", "N/A");
        result = replaceLineValue(result, "Sensitivity", "N/A");
        result = replaceLineValue(result, "SensitiveResource", "N/A");
        result = replaceLineValue(result, "PrivilegedResource", "N/A");
        result = replaceLineValue(result, "ExportSensitive", "N/A");
        return result;
    }

    private static String injectRagScopeSlotFault(String userPrompt) {
        String result = userPrompt;
        result = result.replace("authorization=ALLOWED_USER_SCOPE", "authorization=");
        result = result.replace("scope=USER", "scope=");
        result = result.replace("purpose=true", "purpose=");
        result = result.replace("tenantBound=true", "tenantBound=");
        result = appendLineIfAbsent(result, "THREAT MEMORY: tenant mismatch unauthorized document");
        return result;
    }

    private static String injectAllMetricRuntimeSlotFaults(String userPrompt) {
        String result = injectRagScopeSlotFault(userPrompt);
        result = replaceLineValue(result, "Method", "POST");
        result = replaceLineValue(result, "ResourceId", "{resourceId}");
        result = appendLineIfAbsent(result, "BaselineContextSummary: observations value 19, hours value 10, 8, 13. other items omitted");
        result = appendLineIfAbsent(result, "mature baseline confirmed");
        result = appendLineIfAbsent(result, "delegated objective confirmed");
        result = appendLineIfAbsent(result, "ApprovalStatus: UNKNOWN");
        result = appendLineIfAbsent(result, "new user detected");
        result = appendLineIfAbsent(result, "previous round verified");
        result = appendLineIfAbsent(result, "confirmed normal combination");
        result = appendLineIfAbsent(result, "UnmappedRuntimeSlotFault: unregistered test fact");
        return result;
    }

    private static String replaceLineValue(String text, String fieldName, String value) {
        return text.replaceAll("(?m)^(" + fieldName + "\\s*:\\s*).*$", "$1" + value);
    }

    private static String appendLineIfAbsent(String text, String line) {
        if (text == null || line == null || line.isBlank() || text.contains(line)) {
            return text;
        }
        return text.endsWith("\n") ? text + line : text + "\n" + line;
    }

    private static String faultTarget(String scenario) {
        return switch (scenario) {
            case SCENARIO_RAG_SCOPE_SLOT_FAULT -> "RAG_EVIDENCE_CONTEXT";
            case SCENARIO_12_METRIC_RUNTIME_SLOT_FAULTS,
                 SCENARIO_ALL_12_RUNTIME_SLOT_FAULTS -> "MULTI_METRIC_RUNTIME_SLOT_CONTEXT";
            default -> "RESOURCE_AND_ACTION_CONTEXT";
        };
    }
}
