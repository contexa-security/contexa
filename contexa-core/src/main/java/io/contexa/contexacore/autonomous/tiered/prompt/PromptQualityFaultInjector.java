package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

final class PromptQualityFaultInjector {

    static final String SCENARIO_CCSR_RESOURCE_ACTION_NA = "CCSR_RESOURCE_ACTION_NA";

    private PromptQualityFaultInjector() {
    }

    static PromptQualityFaultInjectionResult apply(String userPrompt, SecurityPromptBuildContext buildContext) {
        String scenario = resolveScenario(buildContext);
        if (scenario == null || userPrompt == null || userPrompt.isBlank()) {
            return new PromptQualityFaultInjectionResult(userPrompt, Map.of());
        }

        String modifiedPrompt = switch (scenario) {
            case SCENARIO_CCSR_RESOURCE_ACTION_NA -> injectResourceActionConflict(userPrompt);
            default -> userPrompt;
        };
        if (modifiedPrompt.equals(userPrompt)) {
            return new PromptQualityFaultInjectionResult(userPrompt, Map.of());
        }

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("pqaPromptFaultApplied", true);
        metadata.put("pqaPromptFaultScenario", scenario);
        metadata.put("pqaPromptFaultTarget", "RESOURCE_AND_ACTION_CONTEXT");
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

    private static String replaceLineValue(String text, String fieldName, String value) {
        return text.replaceAll("(?m)^(" + fieldName + "\\s*:\\s*).*$", "$1" + value);
    }
}
