package io.contexa.contexacore.verification.runtime.prompt;

import java.util.List;

public record FinalPromptMetricContract(
        String metricCode,
        String version,
        String purpose,
        String qualityQuestion,
        String metricRole,
        boolean blocksLlmSubmission,
        boolean blocksCertificate,
        List<FinalPromptMetricCheckContract> checks
) {

    public FinalPromptMetricContract {
        checks = copyChecks(checks);
    }

    private static List<FinalPromptMetricCheckContract> copyChecks(List<FinalPromptMetricCheckContract> values) {
        if (values == null) {
            return List.of();
        }
        for (int index = 0; index < values.size(); index++) {
            if (values.get(index) == null) {
                throw new IllegalArgumentException("Final prompt metric contract checks contains null at index "
                        + index + ".");
            }
        }
        return List.copyOf(values);
    }
}
