package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacommon.enums.ZeroTrustAction;

import java.util.List;

public record PromptDecisionAdjustment(
        boolean applied,
        boolean confidenceAdjusted,
        boolean autonomyConstrained,
        ZeroTrustAction enforcementAction,
        Double effectiveConfidence,
        List<String> reasons,
        String summary) {

    public static PromptDecisionAdjustment noChange(Double confidence) {
        return new PromptDecisionAdjustment(
                false,
                false,
                false,
                null,
                confidence,
                List.of(),
                null
        );
    }
}
