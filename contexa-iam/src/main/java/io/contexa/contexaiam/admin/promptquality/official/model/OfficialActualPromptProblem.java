package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record OfficialActualPromptProblem(
        String problemId,
        String packageId,
        String aggregateRunId,
        String fieldKey,
        String problemType,
        String promptSection,
        String promptLabel,
        String promptValue,
        String sourceFieldPath,
        String sealedEvidencePath,
        String expectedState,
        String actualState,
        String severity,
        List<String> metricCodes,
        String remediationOwner,
        String qualityQuestion,
        String whyItMatters,
        String fixAction,
        String reverifyCriterionDetail,
        List<String> runtimeFacts,
        List<String> contextItems) {

    public OfficialActualPromptProblem {
        metricCodes = metricCodes == null ? List.of() : List.copyOf(metricCodes);
        runtimeFacts = runtimeFacts == null ? List.of() : List.copyOf(runtimeFacts);
        contextItems = contextItems == null ? List.of() : List.copyOf(contextItems);
    }
}
