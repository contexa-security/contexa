package io.contexa.contexacore.verification.metric;

public record OfficialVerificationMetricDefinition(
        String code,
        String metricName,
        String category,
        String description,
        boolean higherIsBetter,
        double benchmarkSuccessThreshold,
        boolean official
) {

    public boolean decisionMetric() {
        return "LLM_DECISION".equals(category);
    }

    public boolean decisionGateMetric() {
        return "LLM_DECISION_GATE".equals(category);
    }

    public boolean contextMetric() {
        return "IMPLEMENTATION_ALIGNMENT".equals(category)
                || "RAG_AND_BASELINE".equals(category)
                || "BEHAVIORAL_CONTEXT".equals(category);
    }

    public boolean resourceEligibilityMetric() {
        return "RESOURCE_ELIGIBILITY".equals(category);
    }
}
