package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record OfficialVerificationPromptComparison(
        String fieldKey,
        String fieldLabel,
        String sealedEvidenceValue,
        String promptValue,
        String officialFactValue,
        String state,
        String stateLabel,
        String meaning,
        List<String> metricCodes,
        List<String> checkCodes,
        List<String> findingIds,
        List<String> issueIds,
        List<String> remediationGroupIds,
        String promptLocation,
        String evidenceSource,
        String recommendedOwner,
        String canonicalSource) {

    public OfficialVerificationPromptComparison {
        metricCodes = metricCodes == null ? List.of() : List.copyOf(metricCodes);
        checkCodes = checkCodes == null ? List.of() : List.copyOf(checkCodes);
        findingIds = findingIds == null ? List.of() : List.copyOf(findingIds);
        issueIds = issueIds == null ? List.of() : List.copyOf(issueIds);
        remediationGroupIds = remediationGroupIds == null ? List.of() : List.copyOf(remediationGroupIds);
    }

    public OfficialVerificationPromptComparison(
            String fieldKey,
            String fieldLabel,
            String sealedEvidenceValue,
            String promptValue,
            String officialFactValue,
            String state,
            String stateLabel,
            String meaning,
            List<String> metricCodes,
            String promptLocation,
            String evidenceSource,
            String recommendedOwner) {
        this(
                fieldKey,
                fieldLabel,
                sealedEvidenceValue,
                promptValue,
                officialFactValue,
                state,
                stateLabel,
                meaning,
                metricCodes,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                promptLocation,
                evidenceSource,
                recommendedOwner,
                "PROMPT_COMPARISON");
    }

    public OfficialVerificationPromptComparison(
            String fieldKey,
            String fieldLabel,
            String sealedEvidenceValue,
            String promptValue,
            String officialFactValue,
            String state,
            String stateLabel,
            String meaning) {
        this(
                fieldKey,
                fieldLabel,
                sealedEvidenceValue,
                promptValue,
                officialFactValue,
                state,
                stateLabel,
                meaning,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                "",
                "",
                "",
                "PROMPT_COMPARISON");
    }
}

