package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

final class SandboxDecisionAggregateReportWriter {

    private final ObjectMapper objectMapper;
    private final Path reportDirectory;

    SandboxDecisionAggregateReportWriter(ObjectMapper objectMapper, Path reportDirectory) {
        this.objectMapper = objectMapper;
        this.reportDirectory = reportDirectory;
    }

    void write(List<SandboxDecisionBenchmarkRunResult> runResults) {
        try {
            Files.createDirectories(reportDirectory);

            Map<String, Object> summary = buildSummary(runResults);
            Files.writeString(
                    reportDirectory.resolve("decision-summary.json"),
                    objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(summary));
            Files.writeString(
                    reportDirectory.resolve("decision-summary.md"),
                    buildMarkdown(summary));
            Files.writeString(
                    reportDirectory.resolve("decision-summary.html"),
                    buildHtml(summary));
            Map<String, Object> performanceSummary = buildPerformanceSummary(runResults);
            Files.writeString(
                    reportDirectory.resolve("decision-performance-summary.json"),
                    objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(performanceSummary));
            Files.writeString(
                    reportDirectory.resolve("decision-performance-summary.md"),
                    buildPerformanceMarkdown(performanceSummary));
            Files.writeString(
                    reportDirectory.resolve("decision-performance-summary.html"),
                    buildPerformanceHtml(performanceSummary));
            writeNdjson(reportDirectory.resolve("decision-metrics.ndjson"), metricRows(runResults));
            writeNdjson(reportDirectory.resolve("decision-runs.ndjson"), runRows(runResults));
            writeNdjson(reportDirectory.resolve("decision-rounds.ndjson"), roundRows(runResults));
            writeNdjson(reportDirectory.resolve("decision-defects.ndjson"), defectRows(runResults));
            writeNdjson(reportDirectory.resolve("decision-performance-rounds.ndjson"), performanceRoundRows(runResults));
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to write aggregate decision benchmark report", exception);
        }
    }

    private Map<String, Object> buildSummary(List<SandboxDecisionBenchmarkRunResult> runResults) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("generatedAt", Instant.now().toString());
        summary.put("boundaryMode", SandboxDecisionBenchmarkSettings.boundaryMode());
        summary.put("realLlmMode", SandboxDecisionBenchmarkSettings.useRealLlm());
        summary.put("modelId", SandboxDecisionBenchmarkSettings.pinnedModelId());
        summary.put("goldVersion", SandboxDecisionBenchmarkSettings.goldVersion());
        summary.put("adjudicationVersion", SandboxDecisionBenchmarkSettings.adjudicationVersion());
        summary.put("scenarioSelector", SandboxDecisionBenchmarkSettings.scenarioSelector());
        summary.put("sampleCount", SandboxDecisionBenchmarkSettings.sampleCount());
        summary.put("configuredRoundCount", SandboxDecisionBenchmarkSettings.roundCount());
        summary.put("runCount", runResults.size());
        summary.put("roundCount", runResults.stream().mapToInt(result -> result.roundResults().size()).sum());
        summary.put("scenarioKeys", runResults.stream()
                .map(result -> result.replayRun().scenarioKey())
                .distinct()
                .sorted()
                .toList());
        summary.put("scenarioFamilies", runResults.stream()
                .map(result -> result.replayRun().scenario().scenarioFamily())
                .distinct()
                .sorted()
                .toList());
        summary.put("userProfileKeys", runResults.stream()
                .map(result -> result.replayRun().scenario().userProfileKey())
                .distinct()
                .sorted()
                .toList());
        summary.put("officialDecisionMetricCount", SandboxDecisionMetric.values().length);
        summary.put("metrics", metricSummary(runResults));
        summary.put("performance", buildPerformanceSummary(runResults));
        summary.put("reportFiles", Map.ofEntries(
                Map.entry("decisionSummaryJson", "decision-summary.json"),
                Map.entry("decisionSummaryMd", "decision-summary.md"),
                Map.entry("decisionSummaryHtml", "decision-summary.html"),
                Map.entry("decisionPerformanceSummaryJson", "decision-performance-summary.json"),
                Map.entry("decisionPerformanceSummaryMd", "decision-performance-summary.md"),
                Map.entry("decisionPerformanceSummaryHtml", "decision-performance-summary.html"),
                Map.entry("decisionIndexHtml", "decision-index.html"),
                Map.entry("decisionMetricsNdjson", "decision-metrics.ndjson"),
                Map.entry("decisionRunsNdjson", "decision-runs.ndjson"),
                Map.entry("decisionRoundsNdjson", "decision-rounds.ndjson"),
                Map.entry("decisionDefectsNdjson", "decision-defects.ndjson"),
                Map.entry("decisionPerformanceRoundsNdjson", "decision-performance-rounds.ndjson")));
        return summary;
    }

    private Map<String, Object> metricSummary(List<SandboxDecisionBenchmarkRunResult> runResults) {
        Map<String, Object> metrics = new LinkedHashMap<>();
        for (SandboxDecisionMetric metric : SandboxDecisionMetric.values()) {
            List<Double> values = runResults.stream()
                    .map(result -> result.metrics().get(metric.key()))
                    .filter(value -> value != null)
                    .toList();
            SandboxPromptBenchmarkStatistics.Summary summarized =
                    SandboxPromptBenchmarkStatistics.summarize(
                            values,
                            metric.successThreshold(),
                            metric.higherIsBetter());

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("metricKey", metric.key());
            row.put("metricName", metric.displayName());
            row.put("successThreshold", metric.successThreshold());
            row.put("higherIsBetter", metric.higherIsBetter());
            row.put("sampleCount", summarized.sampleCount());
            row.put("mean", summarized.mean());
            row.put("median", summarized.median());
            row.put("stdDev", summarized.stdDev());
            row.put("min", summarized.min());
            row.put("max", summarized.max());
            row.put("failureRatePercent", summarized.failureRatePercent());
            row.put("ci95Low", summarized.ci95Low());
            row.put("ci95High", summarized.ci95High());
            row.put("stabilityClass", stabilityClass(summarized, metric));
            metrics.put(metric.displayName(), row);
        }
        return metrics;
    }

    private Map<String, Object> buildPerformanceSummary(List<SandboxDecisionBenchmarkRunResult> runResults) {
        List<SandboxDecisionPerformanceTelemetry> telemetryRows = runResults.stream()
                .flatMap(result -> result.roundResults().stream())
                .map(SandboxDecisionRoundResult::performanceTelemetry)
                .filter(java.util.Objects::nonNull)
                .toList();

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("generatedAt", Instant.now().toString());
        summary.put("boundaryMode", SandboxDecisionBenchmarkSettings.boundaryMode());
        summary.put("realLlmMode", SandboxDecisionBenchmarkSettings.useRealLlm());
        summary.put("modelId", SandboxDecisionBenchmarkSettings.pinnedModelId());
        summary.put("runCount", runResults.size());
        summary.put("roundCount", telemetryRows.size());
        summary.put("costProfile", telemetryRows.stream()
                .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                .map(SandboxDecisionCostEstimate::costProfile)
                .filter(java.util.Objects::nonNull)
                .findFirst()
                .map(profile -> Map.of(
                        "profileKey", profile.profileKey(),
                        "displayName", profile.displayName(),
                        "currencyCode", profile.currencyCode(),
                        "configured", profile.configured(),
                        "inputCostPer1kTokens", profile.inputCostPer1kTokens(),
                        "outputCostPer1kTokens", profile.outputCostPer1kTokens()))
                .orElse(Map.of(
                        "profileKey", "UNCONFIGURED",
                        "displayName", "Unconfigured reference pricing",
                        "currencyCode", "USD",
                        "configured", false,
                        "inputCostPer1kTokens", 0.0d,
                        "outputCostPer1kTokens", 0.0d)));
        summary.put("prefillMeasuredRatePercent", round(percentage(telemetryRows.stream()
                .filter(SandboxDecisionPerformanceTelemetry::prefillMeasured)
                .count(), telemetryRows.size())));
        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("promptPrefillLatencyMs", summarizePerformanceMetric(telemetryRows.stream()
                .filter(SandboxDecisionPerformanceTelemetry::prefillMeasured)
                .mapToDouble(SandboxDecisionPerformanceTelemetry::promptPrefillLatencyMs)
                .toArray()));
        metrics.put("promptEndToEndLatencyMs", summarizePerformanceMetric(telemetryRows.stream()
                .mapToDouble(SandboxDecisionPerformanceTelemetry::promptEndToEndLatencyMs)
                .toArray()));
        metrics.put("estimatedRawInputTokens", summarizePerformanceMetric(telemetryRows.stream()
                .mapToDouble(SandboxDecisionPerformanceTelemetry::estimatedRawInputTokens)
                .toArray()));
        metrics.put("estimatedLlmInputTokens", summarizePerformanceMetric(telemetryRows.stream()
                .mapToDouble(SandboxDecisionPerformanceTelemetry::estimatedLlmInputTokens)
                .toArray()));
        metrics.put("estimatedOutputTokens", summarizePerformanceMetric(telemetryRows.stream()
                .mapToDouble(SandboxDecisionPerformanceTelemetry::estimatedOutputTokens)
                .toArray()));
        metrics.put("llmInvocationCount", summarizePerformanceMetric(telemetryRows.stream()
                .mapToDouble(SandboxDecisionPerformanceTelemetry::llmInvocationCount)
                .toArray()));
        metrics.put("tokensPerSecond", summarizePerformanceMetric(telemetryRows.stream()
                .mapToDouble(SandboxDecisionPerformanceTelemetry::tokensPerSecond)
                .toArray()));
        metrics.put("estimatedVendorCostRaw", summarizePerformanceMetric(telemetryRows.stream()
                .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                .filter(java.util.Objects::nonNull)
                .mapToDouble(SandboxDecisionCostEstimate::estimatedVendorCostRaw)
                .toArray()));
        metrics.put("estimatedVendorCostLlm", summarizePerformanceMetric(telemetryRows.stream()
                .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                .filter(java.util.Objects::nonNull)
                .mapToDouble(SandboxDecisionCostEstimate::estimatedVendorCostLlm)
                .toArray()));
        metrics.put("estimatedVendorCostSavings", summarizePerformanceMetric(telemetryRows.stream()
                .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                .filter(java.util.Objects::nonNull)
                .mapToDouble(SandboxDecisionCostEstimate::estimatedVendorCostSavings)
                .toArray()));
        summary.put("metrics", metrics);
        summary.put("reportFiles", Map.of(
                "decisionPerformanceSummaryJson", "decision-performance-summary.json",
                "decisionPerformanceSummaryMd", "decision-performance-summary.md",
                "decisionPerformanceSummaryHtml", "decision-performance-summary.html",
                "decisionPerformanceRoundsNdjson", "decision-performance-rounds.ndjson"));
        return summary;
    }

    private List<Map<String, Object>> metricRows(List<SandboxDecisionBenchmarkRunResult> runResults) {
        return java.util.Arrays.stream(SandboxDecisionMetric.values())
                .map(metric -> {
                    List<Double> values = runResults.stream()
                            .map(result -> result.metrics().get(metric.key()))
                            .filter(value -> value != null)
                            .toList();
                    SandboxPromptBenchmarkStatistics.Summary summarized =
                            SandboxPromptBenchmarkStatistics.summarize(
                                    values,
                                    metric.successThreshold(),
                                    metric.higherIsBetter());
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("metricKey", metric.key());
                    row.put("metricName", metric.displayName());
                    row.put("mean", summarized.mean());
                    row.put("failureRatePercent", summarized.failureRatePercent());
                    row.put("ci95Low", summarized.ci95Low());
                    row.put("ci95High", summarized.ci95High());
                    row.put("stabilityClass", stabilityClass(summarized, metric));
                    return row;
                })
                .toList();
    }

    private List<Map<String, Object>> runRows(List<SandboxDecisionBenchmarkRunResult> runResults) {
        return runResults.stream()
                .map(result -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("benchmarkRunId", result.benchmarkRunId());
                    row.put("username", result.username());
                    row.put("scenarioKey", result.replayRun().scenarioKey());
                    row.put("scenarioFamily", result.replayRun().scenario().scenarioFamily());
                    row.put("userProfileKey", result.replayRun().scenario().userProfileKey());
                    row.put("roundCount", result.roundResults().size());
                    for (SandboxDecisionMetric metric : SandboxDecisionMetric.values()) {
                        row.put(metric.key(), result.metrics().get(metric.key()));
                    }
                    return row;
                })
                .toList();
    }

    private List<Map<String, Object>> roundRows(List<SandboxDecisionBenchmarkRunResult> runResults) {
        return runResults.stream()
                .flatMap(result -> result.roundResults().stream())
                .map(round -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("benchmarkRunId", round.benchmarkRunId());
                    row.put("username", round.username());
                    row.put("scenarioKey", round.scenarioKey());
                    row.put("scenarioFamily", round.scenarioFamily());
                    row.put("roundNumber", round.roundNumber());
                    row.put("roundKey", round.roundKey());
                    row.put("predictedAction", round.predictedAction());
                    row.put("predictedConfidence", round.predictedConfidence());
                    row.put("goldConfidenceBand", round.goldCase().confidenceBand().pretty());
                    row.put("uncertaintyRequired", round.goldCase().uncertaintyRequired());
                    row.put("requiredEvidenceTokens", round.goldCase().requiredEvidenceTokens());
                    row.put("groundedClaimPrecision", round.adjudication().groundedClaimPrecision());
                    row.put("unsupportedClaimRate", round.adjudication().unsupportedClaimRate());
                    row.put("contradictedClaimRate", round.adjudication().contradictedClaimRate());
                    row.put("actionAllowedByGoldCase", round.actionAllowedByGoldCase());
                    row.put("confidenceWithinBand", round.confidenceWithinBand());
                    row.put("unsafeOverconfidence", round.unsafeOverconfidence());
                    row.put("safeUncertaintyPass", round.safeUncertaintyPass());
                    row.put("CDC", round.cdcScore());
                    row.put("ERA", round.eraScore());
                    row.put("SUHR", round.suhrScore());
                    appendPerformanceTelemetry(row, round.performanceTelemetry());
                    return row;
                })
                .toList();
    }

    private List<Map<String, Object>> performanceRoundRows(List<SandboxDecisionBenchmarkRunResult> runResults) {
        return runResults.stream()
                .flatMap(result -> result.roundResults().stream())
                .map(round -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("benchmarkRunId", round.benchmarkRunId());
                    row.put("username", round.username());
                    row.put("scenarioKey", round.scenarioKey());
                    row.put("scenarioFamily", round.scenarioFamily());
                    row.put("roundNumber", round.roundNumber());
                    row.put("roundKey", round.roundKey());
                    row.put("CDC", round.cdcScore());
                    row.put("ERA", round.eraScore());
                    row.put("SUHR", round.suhrScore());
                    appendPerformanceTelemetry(row, round.performanceTelemetry());
                    return row;
                })
                .toList();
    }

    private List<Map<String, Object>> defectRows(List<SandboxDecisionBenchmarkRunResult> runResults) {
        return runResults.stream()
                .flatMap(result -> result.roundResults().stream())
                .flatMap(round -> java.util.Arrays.stream(SandboxDecisionMetric.values())
                        .filter(metric -> metricValue(metric, round) < metric.successThreshold())
                        .map(metric -> {
                            Map<String, Object> row = new LinkedHashMap<>();
                            row.put("metricKey", metric.key());
                            row.put("metricName", metric.displayName());
                            row.put("benchmarkRunId", round.benchmarkRunId());
                            row.put("username", round.username());
                            row.put("scenarioKey", round.scenarioKey());
                            row.put("scenarioFamily", round.scenarioFamily());
                            row.put("roundNumber", round.roundNumber());
                            row.put("roundKey", round.roundKey());
                            row.put("predictedAction", round.predictedAction());
                            row.put("predictedConfidence", round.predictedConfidence());
                            row.put("metricValue", metricValue(metric, round));
                            row.put("successThreshold", metric.successThreshold());
                            row.put("requiredEvidenceTokens", round.goldCase().requiredEvidenceTokens());
                            row.put("defectReason", defectReason(metric, round));
                            return row;
                        }))
                .toList();
    }

    private String buildMarkdown(Map<String, Object> summary) {
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> metrics = (Map<String, Map<String, Object>>) summary.get("metrics");
        return String.format(Locale.ROOT, """
                # Sandbox Decision Benchmark Summary

                - boundaryMode: `%s`
                - realLlmMode: `%s`
                - modelId: `%s`
                - goldVersion: `%s`
                - adjudicationVersion: `%s`
                - scenarioSelector: `%s`
                - runCount: `%s`
                - roundCount: `%s`

                ## Metrics
                %s
                """,
                summary.get("boundaryMode"),
                summary.get("realLlmMode"),
                summary.get("modelId"),
                summary.get("goldVersion"),
                summary.get("adjudicationVersion"),
                summary.get("scenarioSelector"),
                summary.get("runCount"),
                summary.get("roundCount"),
                metrics.entrySet().stream()
                        .map(entry -> {
                            Map<String, Object> metric = entry.getValue();
                            return String.format(
                                    Locale.ROOT,
                                    "- `%s` mean=`%.3f`, failureRatePercent=`%.3f`, ci95=`[%.3f, %.3f]`, stability=`%s`",
                                    entry.getKey(),
                                    asDouble(metric.get("mean")),
                                    asDouble(metric.get("failureRatePercent")),
                                    asDouble(metric.get("ci95Low")),
                                    asDouble(metric.get("ci95High")),
                                    metric.get("stabilityClass"));
                        })
                        .collect(Collectors.joining(System.lineSeparator())));
    }

    private String buildHtml(Map<String, Object> summary) {
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> metrics = (Map<String, Map<String, Object>>) summary.get("metrics");

        StringBuilder builder = new StringBuilder();
        builder.append("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">")
                .append("<title>Sandbox Decision Benchmark Summary</title>")
                .append("<style>")
                .append("body{font-family:'Segoe UI',sans-serif;margin:32px;color:#111827;background:#f9fafb;}")
                .append("table{border-collapse:collapse;width:100%;margin-top:16px;}")
                .append("th,td{border:1px solid #d1d5db;padding:8px;text-align:left;font-size:14px;}")
                .append("th{background:#eef2ff;}a{color:#2563eb;text-decoration:none;}code{background:#e5e7eb;padding:2px 4px;border-radius:4px;}")
                .append("</style></head><body>");
        builder.append("<h1>Sandbox Decision Benchmark Summary</h1>");
        builder.append("<ul>")
                .append("<li>boundaryMode: <code>").append(escapeHtml(String.valueOf(summary.get("boundaryMode")))).append("</code></li>")
                .append("<li>realLlmMode: ").append(escapeHtml(String.valueOf(summary.get("realLlmMode")))).append("</li>")
                .append("<li>modelId: <code>").append(escapeHtml(String.valueOf(summary.get("modelId")))).append("</code></li>")
                .append("<li>goldVersion: <code>").append(escapeHtml(String.valueOf(summary.get("goldVersion")))).append("</code></li>")
                .append("<li>adjudicationVersion: <code>").append(escapeHtml(String.valueOf(summary.get("adjudicationVersion")))).append("</code></li>")
                .append("<li>scenarioSelector: <code>").append(escapeHtml(String.valueOf(summary.get("scenarioSelector")))).append("</code></li>")
                .append("<li>runCount: ").append(escapeHtml(String.valueOf(summary.get("runCount")))).append("</li>")
                .append("<li>roundCount: ").append(escapeHtml(String.valueOf(summary.get("roundCount")))).append("</li>")
                .append("</ul>");
        builder.append("<p>")
                .append("<a href=\"decision-summary.json\">decision-summary.json</a> | ")
                .append("<a href=\"decision-summary.md\">decision-summary.md</a> | ")
                .append("<a href=\"decision-performance-summary.html\">decision-performance-summary.html</a> | ")
                .append("<a href=\"decision-index.html\">decision-index.html</a> | ")
                .append("<a href=\"decision-metrics.ndjson\">decision-metrics.ndjson</a> | ")
                .append("<a href=\"decision-runs.ndjson\">decision-runs.ndjson</a> | ")
                .append("<a href=\"decision-rounds.ndjson\">decision-rounds.ndjson</a> | ")
                .append("<a href=\"decision-defects.ndjson\">decision-defects.ndjson</a> | ")
                .append("<a href=\"decision-performance-rounds.ndjson\">decision-performance-rounds.ndjson</a>")
                .append("</p>");
        builder.append("<h2>Metric Summary</h2><table><thead><tr>")
                .append("<th>Metric</th><th>Mean</th><th>Failure Rate</th><th>95% CI</th><th>Stability</th><th>Artifacts</th>")
                .append("</tr></thead><tbody>");
        for (SandboxDecisionMetric metric : SandboxDecisionMetric.values()) {
            Map<String, Object> metricSummary = metrics.get(metric.displayName());
            builder.append("<tr><td>").append(escapeHtml(metric.displayName())).append("</td>")
                    .append("<td>").append(formatNumber(metricSummary.get("mean"))).append("</td>")
                    .append("<td>").append(formatNumber(metricSummary.get("failureRatePercent"))).append("%</td>")
                    .append("<td>[")
                    .append(formatNumber(metricSummary.get("ci95Low")))
                    .append(", ")
                    .append(formatNumber(metricSummary.get("ci95High")))
                    .append("]</td>")
                    .append("<td>").append(escapeHtml(String.valueOf(metricSummary.get("stabilityClass")))).append("</td>")
                    .append("<td><a href=\"").append(metric.key()).append("/").append(metric.key()).append("-summary.html\">")
                    .append(metric.key()).append("</a></td></tr>");
        }
        builder.append("</tbody></table></body></html>");
        return builder.toString();
    }

    private String stabilityClass(SandboxPromptBenchmarkStatistics.Summary summary, SandboxDecisionMetric metric) {
        if (summary.sampleCount() <= 1) {
            return "STABLE";
        }
        if (summary.failureRatePercent() > 0.0d) {
            return "FLAKY";
        }
        if (!metric.higherIsBetter() && summary.max() > 0.0d) {
            return "VARIABLE";
        }
        double meanAbs = Math.abs(summary.mean());
        if (meanAbs < 0.000001d) {
            return "STABLE";
        }
        double coefficientOfVariationPercent = (summary.stdDev() / meanAbs) * 100.0d;
        if (coefficientOfVariationPercent >= 5.0d || summary.stdDev() >= 3.0d) {
            return "VARIABLE";
        }
        return "STABLE";
    }

    private double metricValue(SandboxDecisionMetric metric, SandboxDecisionRoundResult round) {
        return switch (metric) {
            case CDC -> round.cdcScore();
            case ERA -> round.eraScore();
            case SUHR -> round.suhrScore();
        };
    }

    private String defectReason(SandboxDecisionMetric metric, SandboxDecisionRoundResult round) {
        return switch (metric) {
            case CDC -> "actionAllowed=%s, confidenceWithinBand=%s, unsafeOverconfidence=%s, groundedClaimPrecision=%s, contradictedClaimRate=%s, requiredEvidenceCovered=%s, safeUncertaintyPass=%s"
                    .formatted(
                            round.actionAllowedByGoldCase(),
                            round.confidenceWithinBand(),
                            round.unsafeOverconfidence(),
                            formatNumber(round.adjudication().groundedClaimPrecision()),
                            formatNumber(round.adjudication().contradictedClaimRate()),
                            round.adjudication().requiredEvidenceCovered(),
                            round.safeUncertaintyPass());
            case ERA -> "groundedClaimPrecision=%s, unsupportedClaimRate=%s, contradictedClaimRate=%s, requiredEvidenceCovered=%s"
                    .formatted(
                            formatNumber(round.adjudication().groundedClaimPrecision()),
                            formatNumber(round.adjudication().unsupportedClaimRate()),
                            formatNumber(round.adjudication().contradictedClaimRate()),
                            round.adjudication().requiredEvidenceCovered());
            case SUHR -> "uncertaintyRequired=%s, safeUncertaintyPass=%s, unsafeOverconfidence=%s"
                    .formatted(round.goldCase().uncertaintyRequired(), round.safeUncertaintyPass(), round.unsafeOverconfidence());
        };
    }

    private void appendPerformanceTelemetry(Map<String, Object> row, SandboxDecisionPerformanceTelemetry telemetry) {
        if (telemetry == null) {
            return;
        }
        row.put("promptStartAtEpochMs", telemetry.promptStartAtEpochMs());
        row.put("firstResponseAtEpochMs", telemetry.firstResponseAtEpochMs());
        row.put("completedAtEpochMs", telemetry.completedAtEpochMs());
        row.put("promptPrefillLatencyMs", telemetry.promptPrefillLatencyMs());
        row.put("promptEndToEndLatencyMs", telemetry.promptEndToEndLatencyMs());
        row.put("prefillMeasured", telemetry.prefillMeasured());
        row.put("estimatedRawInputTokens", telemetry.estimatedRawInputTokens());
        row.put("estimatedLlmInputTokens", telemetry.estimatedLlmInputTokens());
        row.put("estimatedOutputTokens", telemetry.estimatedOutputTokens());
        row.put("llmInvocationCount", telemetry.llmInvocationCount());
        row.put("structuredAttempted", telemetry.structuredAttempted());
        row.put("structuredSucceeded", telemetry.structuredSucceeded());
        row.put("repairAttempted", telemetry.repairAttempted());
        row.put("repairSucceeded", telemetry.repairSucceeded());
        row.put("tokensPerSecond", telemetry.tokensPerSecond());
        SandboxDecisionCostEstimate costEstimate = telemetry.costEstimate();
        if (costEstimate != null) {
            SandboxDecisionCostProfile costProfile = costEstimate.costProfile();
            if (costProfile != null) {
                row.put("costProfileKey", costProfile.profileKey());
                row.put("costCurrencyCode", costProfile.currencyCode());
                row.put("costProfileInfrastructurePerHour", costProfile.infrastructureCostPerHour());
                row.put("costProfileConfigured", costProfile.configured());
            }
            row.put("estimatedVendorCostRaw", costEstimate.estimatedVendorCostRaw());
            row.put("estimatedVendorCostLlm", costEstimate.estimatedVendorCostLlm());
            row.put("estimatedVendorCostSavings", costEstimate.estimatedVendorCostSavings());
            row.put("estimatedInfrastructureCostRaw", costEstimate.estimatedInfrastructureCostRaw());
            row.put("estimatedInfrastructureCostLlm", costEstimate.estimatedInfrastructureCostLlm());
            row.put("estimatedInfrastructureCostSavings", costEstimate.estimatedInfrastructureCostSavings());
        }
    }

    private Map<String, Object> summarizePerformanceMetric(double[] values) {
        List<Double> samples = java.util.Arrays.stream(values)
                .boxed()
                .toList();
        SandboxPromptBenchmarkStatistics.Summary summary =
                SandboxPromptBenchmarkStatistics.summarize(samples, 0.0d, true);
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("sampleCount", summary.sampleCount());
        row.put("mean", summary.mean());
        row.put("median", summary.median());
        row.put("stdDev", summary.stdDev());
        row.put("min", summary.min());
        row.put("max", summary.max());
        row.put("ci95Low", summary.ci95Low());
        row.put("ci95High", summary.ci95High());
        return row;
    }

    private String buildPerformanceMarkdown(Map<String, Object> performanceSummary) {
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> metrics = (Map<String, Map<String, Object>>) performanceSummary.get("metrics");
        return String.format(Locale.ROOT, """
                # Decision Performance Summary

                - boundaryMode: `%s`
                - realLlmMode: `%s`
                - modelId: `%s`
                - runCount: `%s`
                - roundCount: `%s`

                ## Performance Metrics
                %s
                """,
                performanceSummary.get("boundaryMode"),
                performanceSummary.get("realLlmMode"),
                performanceSummary.get("modelId"),
                performanceSummary.get("runCount"),
                performanceSummary.get("roundCount"),
                metrics.entrySet().stream()
                        .map(entry -> {
                            Map<String, Object> metric = entry.getValue();
                            return String.format(
                                    Locale.ROOT,
                                    "- `%s` mean=`%.3f`, median=`%.3f`, min/max=`%.3f / %.3f`, ci95=`[%.3f, %.3f]`",
                                    entry.getKey(),
                                    asDouble(metric.get("mean")),
                                    asDouble(metric.get("median")),
                                    asDouble(metric.get("min")),
                                    asDouble(metric.get("max")),
                                    asDouble(metric.get("ci95Low")),
                                    asDouble(metric.get("ci95High")));
                        })
                        .collect(Collectors.joining(System.lineSeparator())));
    }

    private String buildPerformanceHtml(Map<String, Object> performanceSummary) {
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> metrics = (Map<String, Map<String, Object>>) performanceSummary.get("metrics");
        StringBuilder builder = new StringBuilder();
        builder.append("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">")
                .append("<title>Decision Performance Summary</title>")
                .append("<style>")
                .append("body{font-family:'Segoe UI',sans-serif;margin:32px;color:#111827;background:#f9fafb;}")
                .append("table{border-collapse:collapse;width:100%;margin-top:16px;}")
                .append("th,td{border:1px solid #d1d5db;padding:8px;text-align:left;font-size:14px;}")
                .append("th{background:#eef2ff;}a{color:#2563eb;text-decoration:none;}code{background:#e5e7eb;padding:2px 4px;border-radius:4px;}")
                .append("</style></head><body>");
        builder.append("<h1>Decision Performance Summary</h1>");
        builder.append("<ul>")
                .append("<li>boundaryMode: <code>").append(escapeHtml(String.valueOf(performanceSummary.get("boundaryMode")))).append("</code></li>")
                .append("<li>realLlmMode: ").append(escapeHtml(String.valueOf(performanceSummary.get("realLlmMode")))).append("</li>")
                .append("<li>modelId: <code>").append(escapeHtml(String.valueOf(performanceSummary.get("modelId")))).append("</code></li>")
                .append("<li>runCount: ").append(escapeHtml(String.valueOf(performanceSummary.get("runCount")))).append("</li>")
                .append("<li>roundCount: ").append(escapeHtml(String.valueOf(performanceSummary.get("roundCount")))).append("</li>")
                .append("</ul>");
        builder.append("<p>")
                .append("<a href=\"decision-performance-summary.json\">decision-performance-summary.json</a> | ")
                .append("<a href=\"decision-performance-summary.md\">decision-performance-summary.md</a> | ")
                .append("<a href=\"decision-performance-rounds.ndjson\">decision-performance-rounds.ndjson</a> | ")
                .append("<a href=\"decision-summary.html\">decision-summary.html</a>")
                .append("</p>");
        builder.append("<h2>Metric Summary</h2><table><thead><tr>")
                .append("<th>Metric</th><th>Mean</th><th>Median</th><th>Min</th><th>Max</th><th>95% CI</th>")
                .append("</tr></thead><tbody>");
        for (Map.Entry<String, Map<String, Object>> entry : metrics.entrySet()) {
            Map<String, Object> metric = entry.getValue();
            builder.append("<tr><td>").append(escapeHtml(entry.getKey())).append("</td>")
                    .append("<td>").append(formatNumber(metric.get("mean"))).append("</td>")
                    .append("<td>").append(formatNumber(metric.get("median"))).append("</td>")
                    .append("<td>").append(formatNumber(metric.get("min"))).append("</td>")
                    .append("<td>").append(formatNumber(metric.get("max"))).append("</td>")
                    .append("<td>[")
                    .append(formatNumber(metric.get("ci95Low")))
                    .append(", ")
                    .append(formatNumber(metric.get("ci95High")))
                    .append("]</td></tr>");
        }
        builder.append("</tbody></table></body></html>");
        return builder.toString();
    }

    private void writeNdjson(Path path, List<Map<String, Object>> rows) throws IOException {
        StringBuilder builder = new StringBuilder();
        for (Map<String, Object> row : rows) {
            builder.append(objectMapper.writeValueAsString(row)).append('\n');
        }
        Files.writeString(path, builder.toString());
    }

    private double asDouble(Object value) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value instanceof String text) {
            try {
                return Double.parseDouble(text);
            } catch (NumberFormatException ignored) {
                return 0.0d;
            }
        }
        return 0.0d;
    }

    private String formatNumber(Object value) {
        if (value instanceof Number number) {
            return String.format(Locale.ROOT, "%.3f", number.doubleValue());
        }
        return escapeHtml(String.valueOf(value));
    }

    private double percentage(long numerator, int denominator) {
        return denominator <= 0 ? 0.0d : (numerator * 100.0d) / denominator;
    }

    private double round(double value) {
        return Math.round(value * 1000.0d) / 1000.0d;
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
