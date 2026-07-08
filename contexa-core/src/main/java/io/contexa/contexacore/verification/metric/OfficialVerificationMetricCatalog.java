package io.contexa.contexacore.verification.metric;

import java.util.List;

public class OfficialVerificationMetricCatalog {

    private final List<OfficialVerificationMetricDefinition> promptMetrics = List.of(
            metric("EIR", "Event Integrity Rate", "IMPLEMENTATION_ALIGNMENT", "Validate that request-originated events preserve the expected field contract.", true, 95.0d),
            metric("CCR", "Context Completeness Rate", "IMPLEMENTATION_ALIGNMENT", "Validate that required session, behavior, retrieval, and prompt metadata fields are populated.", true, 95.0d),
            metric("CCSR", "Context Consistency Rate", "IMPLEMENTATION_ALIGNMENT", "Validate that the same facts stay consistent across event, context, prompt, and evidence views.", true, 95.0d),
            metric("PFR", "Prompt Fidelity Rate", "IMPLEMENTATION_ALIGNMENT", "Validate that generated prompt artifacts match the official template contract.", true, 95.0d),
            metric("MTR", "Metadata Traceability Rate", "IMPLEMENTATION_ALIGNMENT", "Validate that request, prompt, evidence, and telemetry linkage remains intact end-to-end.", true, 95.0d),
            metric("COR", "Context Contamination Rate", "IMPLEMENTATION_ALIGNMENT", "Validate that foreign-user, foreign-purpose, or unauthorized documents never contaminate the context.", true, 95.0d),
            metric("RAP", "RAG Authorization Precision", "RAG_AND_BASELINE", "Validate that only authorized retrieved documents survive into the final context.", true, 95.0d),
            metric("RPI", "Round Progression Integrity", "RAG_AND_BASELINE", "Validate that memory, baseline, and retrieval evidence progress without regression across rounds.", true, 95.0d),
            metric("BMA", "Baseline Maturity Accuracy", "RAG_AND_BASELINE", "Validate that baseline maturity states reflect real observation depth without overclaiming.", true, 95.0d),
            metric("USNS", "User-Specific Novelty Sensitivity", "BEHAVIORAL_CONTEXT", "Validate that user-specific novelty is detected even when coarse device and network signals look normal.", true, 95.0d),
            metric("BSR", "Behavioral Surprise Resolution", "BEHAVIORAL_CONTEXT", "Validate that sequence jumps, oscillation, and friction deviations are surfaced and explained.", true, 95.0d),
            metric("PRE", "Protectable Resource Eligibility", "RESOURCE_ELIGIBILITY", "Validate that the target URL is backed by @Protectable resource metadata, certificate evidence, and Zero Trust enablement gates.", true, 100.0d)
    );

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

    public List<OfficialVerificationMetricDefinition> decisionGateMetrics() {
        return List.of();
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
