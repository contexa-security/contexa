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
            writeNdjson(reportDirectory.resolve("decision-metrics.ndjson"), metricRows(runResults));
            writeNdjson(reportDirectory.resolve("decision-runs.ndjson"), runRows(runResults));
            writeNdjson(reportDirectory.resolve("decision-rounds.ndjson"), roundRows(runResults));
            writeNdjson(reportDirectory.resolve("decision-defects.ndjson"), defectRows(runResults));
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
        summary.put("reportFiles", Map.of(
                "decisionSummaryJson", "decision-summary.json",
                "decisionSummaryMd", "decision-summary.md",
                "decisionSummaryHtml", "decision-summary.html",
                "decisionIndexHtml", "decision-index.html",
                "decisionMetricsNdjson", "decision-metrics.ndjson",
                "decisionRunsNdjson", "decision-runs.ndjson",
                "decisionRoundsNdjson", "decision-rounds.ndjson",
                "decisionDefectsNdjson", "decision-defects.ndjson"));
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
                .append("<a href=\"decision-index.html\">decision-index.html</a> | ")
                .append("<a href=\"decision-metrics.ndjson\">decision-metrics.ndjson</a> | ")
                .append("<a href=\"decision-runs.ndjson\">decision-runs.ndjson</a> | ")
                .append("<a href=\"decision-rounds.ndjson\">decision-rounds.ndjson</a> | ")
                .append("<a href=\"decision-defects.ndjson\">decision-defects.ndjson</a>")
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
