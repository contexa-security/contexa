package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class PromptRuntimeTelemetrySupport {

    private static final List<String> RUNTIME_TELEMETRY_KEYS = List.of(
            "promptKey",
            "templateKey",
            "promptVersion",
            "contractVersion",
            "promptReleaseStatus",
            "promptOwner",
            "promptReleaseApprovalReference",
            "promptEvaluationBaselineReference",
            "promptRollbackVersion",
            "promptChangeSummary",
            "promptSupportedModelProfiles",
            "promptTemplateClass",
            "budgetProfile",
            "budgetProfileDescription",
            "budgetMaxInputTokens",
            "budgetSystemReserveTokens",
            "budgetUserReserveTokens",
            "budgetOutputReserveTokens",
            "budgetExpansionAllowed",
            "promptSectionSet",
            "omittedSections",
            "omissionLedger",
            "promptEvidenceCompleteness",
            "promptOmissionCount",
            "promptHash",
            "systemPromptHash",
            "userPromptHash",
            "systemPromptLength",
            "userPromptLength",
            "totalPromptLength",
            "promptGeneratedAtEpochMs"
    );

    private PromptRuntimeTelemetrySupport() {
    }

    public static List<String> runtimeTelemetryKeys() {
        return RUNTIME_TELEMETRY_KEYS;
    }

    public static Map<String, Object> extractRuntimeTelemetry(Map<String, Object> metadata) {
        Map<String, Object> telemetry = new LinkedHashMap<>();
        if (metadata == null || metadata.isEmpty()) {
            return telemetry;
        }
        for (String key : RUNTIME_TELEMETRY_KEYS) {
            Object value = metadata.get(key);
            if (value != null) {
                telemetry.put(key, value);
            }
        }
        return telemetry;
    }
}
