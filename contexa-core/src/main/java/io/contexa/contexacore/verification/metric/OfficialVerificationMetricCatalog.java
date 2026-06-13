package io.contexa.contexacore.verification.metric;

import java.util.List;

public class OfficialVerificationMetricCatalog {

    private final List<OfficialVerificationMetricDefinition> metrics = List.of(
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
            metric("CDC", "Context-to-Decision Calibration", "LLM_DECISION", "Validate that decision confidence, risk, and action stay calibrated to context quality.", true, 95.0d),
            metric("ERA", "Evidence-Reason Alignment", "LLM_DECISION", "Validate that reasoning claims are fully grounded in collected evidence.", true, 95.0d),
            metric("SUHR", "Safe-Uncertainty Handling Rate", "LLM_DECISION", "Validate that ambiguous cases resolve to safe challenge or escalation behavior instead of permissive allowance.", true, 95.0d),
            metric("PRE", "Protectable Resource Eligibility", "RESOURCE_ELIGIBILITY", "Validate that the target URL is backed by @Protectable resource metadata, certificate evidence, and Zero Trust enablement gates.", true, 100.0d)
    );

    public List<OfficialVerificationMetricDefinition> allMetrics() {
        return metrics;
    }

    public List<OfficialVerificationMetricDefinition> promptQualityMetrics() {
        return metrics.stream()
                .filter(metric -> metric.contextMetric() || metric.resourceEligibilityMetric())
                .toList();
    }

    public List<OfficialVerificationMetricDefinition> contextMetrics() {
        return metrics.stream()
                .filter(OfficialVerificationMetricDefinition::contextMetric)
                .toList();
    }

    public List<OfficialVerificationMetricDefinition> decisionMetrics() {
        return metrics.stream()
                .filter(OfficialVerificationMetricDefinition::decisionMetric)
                .toList();
    }

    public OfficialVerificationMetricDefinition findRequiredMetric(String metricCode) {
        return metrics.stream()
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
