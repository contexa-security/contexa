package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record OfficialMetricPurposeEvidence(
        String metricCode,
        String checkCode,
        String contractVersion,
        String signalKey,
        String promptLocation,
        String evidenceValue,
        String evidenceHash,
        String interpretation,
        String purposeResult,
        boolean customerVisible,
        String readinessScope,
        List<String> runtimeFacts,
        List<String> contextItems) {

    public OfficialMetricPurposeEvidence {
        runtimeFacts = runtimeFacts == null ? List.of() : List.copyOf(runtimeFacts);
        contextItems = contextItems == null ? List.of() : List.copyOf(contextItems);
    }
}
