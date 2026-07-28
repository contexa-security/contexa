package io.contexa.contexacore.verification.metric;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;

import java.util.List;

public class OfficialVerificationMetricCatalog {

    private final List<OfficialVerificationMetricDefinition> promptMetrics;

    public OfficialVerificationMetricCatalog() {
        this(FinalPromptMetricContractCatalog.load(new ObjectMapper()));
    }

    OfficialVerificationMetricCatalog(FinalPromptMetricContractCatalog contractCatalog) {
        this.promptMetrics = contractCatalog.metrics().stream()
                .map(metric -> metric(
                        metric.metricCode(),
                        metric.metricName(),
                        metric.metricGroup(),
                        metric.purpose(),
                        metric.higherIsBetter(),
                        metric.benchmarkSuccessThreshold()))
                .toList();
    }

    public List<OfficialVerificationMetricDefinition> allMetrics() {
        return promptMetrics;
    }

    public List<OfficialVerificationMetricDefinition> promptQualityMetrics() {
        return promptMetrics;
    }

    public List<OfficialVerificationMetricDefinition> contextMetrics() {
        return promptMetrics.stream()
                .filter(OfficialVerificationMetricDefinition::contextMetric)
                .toList();
    }

    public List<OfficialVerificationMetricDefinition> decisionMetrics() {
        return List.of();
    }

    public List<OfficialVerificationMetricDefinition> allDecisionMetrics() {
        return List.of();
    }

    public OfficialVerificationMetricDefinition findRequiredMetric(String metricCode) {
        return allMetrics().stream()
                .filter(metric -> metric.code().equalsIgnoreCase(metricCode))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown official verification metric: " + metricCode));
    }

    private static OfficialVerificationMetricDefinition metric(
            String code,
            String metricName,
            String category,
            String description,
            boolean higherIsBetter,
            double benchmarkSuccessThreshold
    ) {
        return new OfficialVerificationMetricDefinition(
                code,
                metricName,
                category,
                description,
                higherIsBetter,
                benchmarkSuccessThreshold,
                true
        );
    }
}
