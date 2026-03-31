package io.contexa.sandbox.fullstack.prompt;

/**
 * metric별 성공 기준과 방향성.
 *
 * 대부분의 정합성 지표는 높을수록 좋지만, contamination rate는 0에 가까울수록 좋다.
 */
public final class SandboxPromptBenchmarkMetricPolicy {

    private SandboxPromptBenchmarkMetricPolicy() {
    }

    public static MetricRule ruleFor(String metricName) {
        return SandboxPromptBenchmarkMetricCatalog.findByMetricName(metricName)
                .map(metric -> new MetricRule(metric.successThreshold(), metric.higherIsBetter()))
                .orElseGet(() -> "Context Contamination Rate".equals(metricName)
                        ? new MetricRule(0.0d, false)
                        : new MetricRule(95.0d, true));
    }

    public record MetricRule(double successThreshold, boolean higherIsBetter) {
    }
}
