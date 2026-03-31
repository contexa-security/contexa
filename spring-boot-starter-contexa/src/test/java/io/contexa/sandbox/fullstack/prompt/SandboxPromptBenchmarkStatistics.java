package io.contexa.sandbox.fullstack.prompt;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * sandbox benchmark 통계 계산기.
 *
 * 외부 라이브러리 없이 benchmark 보고에 필요한 기본 통계를 직접 계산한다.
 */
public final class SandboxPromptBenchmarkStatistics {

    private SandboxPromptBenchmarkStatistics() {
    }

    public static Summary summarize(List<Double> values, double successThreshold) {
        return summarize(values, successThreshold, true);
    }

    public static Summary summarize(List<Double> values, double successThreshold, boolean higherIsBetter) {
        List<Double> sanitized = values == null
                ? List.of()
                : values.stream()
                .filter(value -> value != null && !value.isNaN() && !value.isInfinite())
                .sorted(Comparator.naturalOrder())
                .toList();

        if (sanitized.isEmpty()) {
            return new Summary(0, 0.0d, 0.0d, 0.0d, 0.0d, 0.0d, 0.0d, 0.0d, 0.0d, 0.0d, 0.0d, 0.0d);
        }

        double mean = sanitized.stream().mapToDouble(Double::doubleValue).average().orElse(0.0d);
        double median = percentile(sanitized, 50.0d);
        double p90 = percentile(sanitized, 90.0d);
        double p95 = percentile(sanitized, 95.0d);
        double p99 = percentile(sanitized, 99.0d);
        double min = sanitized.get(0);
        double max = sanitized.get(sanitized.size() - 1);

        double variance = 0.0d;
        for (double value : sanitized) {
            double delta = value - mean;
            variance += delta * delta;
        }
        variance = variance / sanitized.size();
        double stdDev = Math.sqrt(variance);
        double standardError = sanitized.isEmpty() ? 0.0d : stdDev / Math.sqrt(sanitized.size());
        double ci95Low = mean - (1.96d * standardError);
        double ci95High = mean + (1.96d * standardError);

        long failures = sanitized.stream()
                .filter(value -> higherIsBetter ? value < successThreshold : value > successThreshold)
                .count();
        double failureRate = sanitized.isEmpty() ? 0.0d : (failures * 100.0d) / sanitized.size();

        return new Summary(
                sanitized.size(),
                mean,
                median,
                stdDev,
                p90,
                p95,
                p99,
                min,
                max,
                failureRate,
                ci95Low,
                ci95High);
    }

    private static double percentile(List<Double> sortedValues, double percentile) {
        if (sortedValues.isEmpty()) {
            return 0.0d;
        }
        if (sortedValues.size() == 1) {
            return sortedValues.get(0);
        }
        double rank = (percentile / 100.0d) * (sortedValues.size() - 1);
        int lowerIndex = (int) Math.floor(rank);
        int upperIndex = (int) Math.ceil(rank);
        if (lowerIndex == upperIndex) {
            return sortedValues.get(lowerIndex);
        }
        double fraction = rank - lowerIndex;
        return sortedValues.get(lowerIndex) + ((sortedValues.get(upperIndex) - sortedValues.get(lowerIndex)) * fraction);
    }

    public record Summary(
            int sampleCount,
            double mean,
            double median,
            double stdDev,
            double p90,
            double p95,
            double p99,
            double min,
            double max,
            double failureRatePercent,
            double ci95Low,
            double ci95High) {

        public String pretty() {
            return String.format(Locale.ROOT,
                    "n=%d, mean=%.2f, median=%.2f, stdDev=%.2f, p90=%.2f, p95=%.2f, p99=%.2f, "
                            + "min=%.2f, max=%.2f, failureRate=%.2f%%, ci95=[%.2f, %.2f]",
                    sampleCount,
                    mean,
                    median,
                    stdDev,
                    p90,
                    p95,
                    p99,
                    min,
                    max,
                    failureRatePercent,
                    ci95Low,
                    ci95High);
        }
    }
}
