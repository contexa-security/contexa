package io.contexa.contexacore.verification.metric;

public enum OfficialVerificationMetricEvaluationStage {
    BENCHMARK_PUBLICATION("BENCHMARK_PUBLICATION"),
    GIVEN_WHEN_THEN_CONTRACT("GIVEN_WHEN_THEN_CONTRACT");

    private final String key;

    OfficialVerificationMetricEvaluationStage(String key) {
        this.key = key;
    }

    public String key() {
        return key;
    }

    public boolean isContractStage() {
        return this == GIVEN_WHEN_THEN_CONTRACT;
    }
}
