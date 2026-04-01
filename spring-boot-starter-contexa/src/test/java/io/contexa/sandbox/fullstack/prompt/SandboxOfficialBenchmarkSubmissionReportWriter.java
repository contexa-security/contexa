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
import java.util.TreeMap;
import java.util.stream.Collectors;

final class SandboxOfficialBenchmarkSubmissionReportWriter {

    private static final String PROMPT_SUMMARY_FILE = "summary.json";
    private static final String DECISION_SUMMARY_FILE = "decision-summary.json";

    private final ObjectMapper objectMapper;
    private final Path reportDirectory;

    SandboxOfficialBenchmarkSubmissionReportWriter(ObjectMapper objectMapper, Path reportDirectory) {
        this.objectMapper = objectMapper;
        this.reportDirectory = reportDirectory;
    }

    void write() {
        try {
            Files.createDirectories(reportDirectory);
            Map<String, Object> promptSummary = readRequiredJson(reportDirectory.resolve(PROMPT_SUMMARY_FILE));
            Map<String, Object> decisionSummary = readRequiredJson(reportDirectory.resolve(DECISION_SUMMARY_FILE));

            Map<String, Object> integratedSummary = buildIntegratedSummary(promptSummary, decisionSummary);
            Files.writeString(
                    reportDirectory.resolve("official-submission-summary.json"),
                    objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(integratedSummary));
            Files.writeString(
                    reportDirectory.resolve("official-submission-summary.md"),
                    buildMarkdown(integratedSummary));
            Files.writeString(
                    reportDirectory.resolve("official-submission-summary.html"),
                    buildHtml(integratedSummary));
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to write official submission benchmark summary", exception);
        }
    }

    private Map<String, Object> buildIntegratedSummary(
            Map<String, Object> promptSummary,
            Map<String, Object> decisionSummary) {
        Map<String, Object> summary = new LinkedHashMap<>();
        Map<String, Object> promptMetricSummaries = mapOfMap(promptSummary.get("metricSummaries"));
        Map<String, Object> decisionMetricSummaries = mapOfMap(decisionSummary.get("metrics"));
        TreeMap<String, Object> combinedMetrics = new TreeMap<>();
        combinedMetrics.putAll(promptMetricSummaries);
        combinedMetrics.putAll(decisionMetricSummaries);

        List<String> implementedOfficialMetrics = SandboxPromptBenchmarkMetricCatalog.implementedOfficialMetrics().stream()
                .map(SandboxPromptBenchmarkMetricCatalog::metricName)
                .filter(combinedMetrics::containsKey)
                .toList();
        List<String> missingImplementedOfficialMetrics = SandboxPromptBenchmarkMetricCatalog.implementedOfficialMetrics().stream()
                .map(SandboxPromptBenchmarkMetricCatalog::metricName)
                .filter(metricName -> !combinedMetrics.containsKey(metricName))
                .toList();
        List<String> failingImplementedOfficialMetrics = SandboxPromptBenchmarkMetricCatalog.implementedOfficialMetrics().stream()
                .filter(metric -> !metricPasses(metric.metricName(), combinedMetrics.get(metric.metricName()), metric.successThreshold()))
                .map(SandboxPromptBenchmarkMetricCatalog::metricName)
                .toList();
        List<String> passedImplementedOfficialMetrics = SandboxPromptBenchmarkMetricCatalog.implementedOfficialMetrics().stream()
                .filter(metric -> metricPasses(metric.metricName(), combinedMetrics.get(metric.metricName()), metric.successThreshold()))
                .map(SandboxPromptBenchmarkMetricCatalog::metricName)
                .toList();
        String officialMetricPassState = missingImplementedOfficialMetrics.isEmpty() && failingImplementedOfficialMetrics.isEmpty()
                ? "COMPLETE"
                : "INCOMPLETE";

        summary.put("generatedAt", Instant.now().toString());
        summary.put("submissionType", "CONTEXA_OFFICIAL_14_METRIC_SUBMISSION");
        summary.put("promptSummaryGeneratedAt", promptSummary.get("generatedAt"));
        summary.put("decisionSummaryGeneratedAt", decisionSummary.get("generatedAt"));
        summary.put("promptBenchmarkVersion", promptSummary.get("benchmarkVersion"));
        summary.put("decisionBoundaryMode", decisionSummary.get("boundaryMode"));
        summary.put("decisionModelId", decisionSummary.get("modelId"));
        summary.put("goldVersion", decisionSummary.get("goldVersion"));
        summary.put("adjudicationVersion", decisionSummary.get("adjudicationVersion"));
        summary.put("officialMetricTargetCount", SandboxPromptBenchmarkMetricCatalog.officialMetrics().size());
        summary.put("implementedOfficialMetricCount", implementedOfficialMetrics.size());
        summary.put("missingImplementedOfficialMetrics", missingImplementedOfficialMetrics);
        summary.put("passedImplementedOfficialMetrics", passedImplementedOfficialMetrics);
        summary.put("failingImplementedOfficialMetrics", failingImplementedOfficialMetrics);
        summary.put("officialMetricPassState", officialMetricPassState);
        summary.put("implementedOfficialMetrics", implementedOfficialMetrics);
        summary.put("combinedMetricSummaries", combinedMetrics);
        summary.put("sourceReports", Map.of(
                "promptSummaryJson", PROMPT_SUMMARY_FILE,
                "promptSummaryHtml", "summary.html",
                "decisionSummaryJson", DECISION_SUMMARY_FILE,
                "decisionSummaryHtml", "decision-summary.html",
                "decisionIndexHtml", "decision-index.html"));
        return summary;
    }

    private boolean metricPasses(String metricName, Object metricSummary, double successThreshold) {
        if (!(metricSummary instanceof Map<?, ?> rawMetricSummary)) {
            return false;
        }
        Object meanValue = rawMetricSummary.get("mean");
        return asDouble(meanValue) >= successThreshold;
    }

    private String buildMarkdown(Map<String, Object> summary) {
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> metrics = (Map<String, Map<String, Object>>) summary.get("combinedMetricSummaries");
        return String.format(Locale.ROOT, """
                # CONTEXA Official 14-Metric Submission Summary

                - officialMetricTargetCount: `%s`
                - implementedOfficialMetricCount: `%s`
                - officialMetricPassState: `%s`
                - promptBenchmarkVersion: `%s`
                - decisionBoundaryMode: `%s`
                - decisionModelId: `%s`
                - goldVersion: `%s`
                - adjudicationVersion: `%s`

                ## Metrics
                %s
                """,
                summary.get("officialMetricTargetCount"),
                summary.get("implementedOfficialMetricCount"),
                summary.get("officialMetricPassState"),
                summary.get("promptBenchmarkVersion"),
                summary.get("decisionBoundaryMode"),
                summary.get("decisionModelId"),
                summary.get("goldVersion"),
                summary.get("adjudicationVersion"),
                metrics.entrySet().stream()
                        .map(entry -> formatMetricLine(entry.getKey(), entry.getValue()))
                        .collect(Collectors.joining(System.lineSeparator())));
    }

    private String buildHtml(Map<String, Object> summary) {
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> metrics = (Map<String, Map<String, Object>>) summary.get("combinedMetricSummaries");
        @SuppressWarnings("unchecked")
        Map<String, Object> sourceReports = (Map<String, Object>) summary.get("sourceReports");

        StringBuilder builder = new StringBuilder();
        builder.append("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">")
                .append("<title>CONTEXA Official 14-Metric Submission Summary</title>")
                .append("<style>")
                .append("body{font-family:'Segoe UI',sans-serif;margin:32px;color:#111827;background:#f9fafb;}")
                .append("table{border-collapse:collapse;width:100%;margin-top:16px;}")
                .append("th,td{border:1px solid #d1d5db;padding:8px;text-align:left;font-size:14px;}")
                .append("th{background:#eef2ff;}a{color:#2563eb;text-decoration:none;}code{background:#e5e7eb;padding:2px 4px;border-radius:4px;}")
                .append("</style></head><body>");
        builder.append("<h1>CONTEXA Official 14-Metric Submission Summary</h1>");
        builder.append("<ul>")
                .append("<li>officialMetricTargetCount: ").append(escapeHtml(String.valueOf(summary.get("officialMetricTargetCount")))).append("</li>")
                .append("<li>implementedOfficialMetricCount: ").append(escapeHtml(String.valueOf(summary.get("implementedOfficialMetricCount")))).append("</li>")
                .append("<li>officialMetricPassState: <code>").append(escapeHtml(String.valueOf(summary.get("officialMetricPassState")))).append("</code></li>")
                .append("<li>promptBenchmarkVersion: <code>").append(escapeHtml(String.valueOf(summary.get("promptBenchmarkVersion")))).append("</code></li>")
                .append("<li>decisionBoundaryMode: <code>").append(escapeHtml(String.valueOf(summary.get("decisionBoundaryMode")))).append("</code></li>")
                .append("<li>decisionModelId: <code>").append(escapeHtml(String.valueOf(summary.get("decisionModelId")))).append("</code></li>")
                .append("<li>goldVersion: <code>").append(escapeHtml(String.valueOf(summary.get("goldVersion")))).append("</code></li>")
                .append("<li>adjudicationVersion: <code>").append(escapeHtml(String.valueOf(summary.get("adjudicationVersion")))).append("</code></li>")
                .append("</ul>");
        builder.append("<p>")
                .append("<a href=\"").append(escapeHtml(String.valueOf(sourceReports.get("promptSummaryHtml")))).append("\">prompt summary</a> | ")
                .append("<a href=\"").append(escapeHtml(String.valueOf(sourceReports.get("decisionSummaryHtml")))).append("\">decision summary</a> | ")
                .append("<a href=\"").append(escapeHtml(String.valueOf(sourceReports.get("decisionIndexHtml")))).append("\">decision index</a> | ")
                .append("<a href=\"official-submission-summary.json\">official-submission-summary.json</a> | ")
                .append("<a href=\"official-submission-summary.md\">official-submission-summary.md</a>")
                .append("</p>");
        builder.append("<h2>Combined Metric Summary</h2><table><thead><tr>")
                .append("<th>Metric</th><th>Mean</th><th>Failure Rate</th><th>95% CI</th><th>Stability</th>")
                .append("</tr></thead><tbody>");
        for (Map.Entry<String, Map<String, Object>> entry : metrics.entrySet()) {
            Map<String, Object> metric = entry.getValue();
            builder.append("<tr><td>").append(escapeHtml(entry.getKey())).append("</td>")
                    .append("<td>").append(formatNumber(metric.get("mean"))).append("</td>")
                    .append("<td>").append(formatNumber(metric.get("failureRatePercent"))).append("%</td>")
                    .append("<td>[")
                    .append(formatNumber(metric.get("ci95Low")))
                    .append(", ")
                    .append(formatNumber(metric.get("ci95High")))
                    .append("]</td>")
                    .append("<td>").append(escapeHtml(String.valueOf(metric.get("stabilityClass")))).append("</td></tr>");
        }
        builder.append("</tbody></table></body></html>");
        return builder.toString();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> readRequiredJson(Path path) throws IOException {
        if (!Files.exists(path)) {
            throw new IllegalStateException("Required benchmark summary is missing: " + path);
        }
        return objectMapper.readValue(Files.readString(path), Map.class);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> mapOfMap(Object value) {
        if (!(value instanceof Map<?, ?> rawMap)) {
            return Map.of();
        }
        Map<String, Object> mapped = new LinkedHashMap<>();
        rawMap.forEach((key, nestedValue) -> mapped.put(String.valueOf(key), nestedValue));
        return mapped;
    }

    @SuppressWarnings("unchecked")
    private String formatMetricLine(String metricName, Map<String, Object> metric) {
        return String.format(
                Locale.ROOT,
                "- `%s` mean=`%.3f`, failureRatePercent=`%.3f`, ci95=`[%.3f, %.3f]`, stability=`%s`",
                metricName,
                asDouble(metric.get("mean")),
                asDouble(metric.get("failureRatePercent")),
                asDouble(metric.get("ci95Low")),
                asDouble(metric.get("ci95High")),
                metric.get("stabilityClass"));
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
