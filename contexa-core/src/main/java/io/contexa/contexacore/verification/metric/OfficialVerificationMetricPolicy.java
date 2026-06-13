package io.contexa.contexacore.verification.metric;

public final class OfficialVerificationMetricPolicy {

    private OfficialVerificationMetricPolicy() {
    }

    public static MetricRule ruleFor(OfficialVerificationMetricDefinition metric) {
        return ruleFor(metric, OfficialVerificationMetricEvaluationStage.BENCHMARK_PUBLICATION);
    }

    public static MetricRule ruleFor(
            OfficialVerificationMetricDefinition metric,
            OfficialVerificationMetricEvaluationStage evaluationStage
    ) {
        if (metric == null) {
            throw new IllegalArgumentException("metric must not be null");
        }
        OfficialVerificationMetricEvaluationStage resolvedStage = evaluationStage != null
                ? evaluationStage
                : OfficialVerificationMetricEvaluationStage.BENCHMARK_PUBLICATION;
        if (resolvedStage.isContractStage() && metric.official()) {
            return new MetricRule(
                    metric.higherIsBetter() ? 100.0d : 0.0d,
                    metric.higherIsBetter(),
                    resolvedStage
            );
        }
        return new MetricRule(
                metric.benchmarkSuccessThreshold(),
                metric.higherIsBetter(),
                resolvedStage
        );
    }

    public record MetricRule(
            double successThreshold,
            boolean higherIsBetter,
            OfficialVerificationMetricEvaluationStage evaluationStage
    ) {
        public boolean passes(double value) {
            return higherIsBetter ? value >= successThreshold : value <= successThreshold;
        }
    }
}
