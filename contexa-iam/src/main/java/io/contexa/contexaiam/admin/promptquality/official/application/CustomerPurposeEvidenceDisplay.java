package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.List;

record CustomerPurposeEvidenceDisplay(
        String signalKey,
        String evidenceValue,
        List<String> runtimeFacts,
        List<String> contextItems,
        boolean structured) {

    CustomerPurposeEvidenceDisplay(String signalKey, String evidenceValue) {
        this(signalKey, evidenceValue, List.of(), List.of(), false);
    }

    CustomerPurposeEvidenceDisplay {
        runtimeFacts = runtimeFacts == null ? List.of() : List.copyOf(runtimeFacts);
        contextItems = contextItems == null ? List.of() : List.copyOf(contextItems);
    }
}
