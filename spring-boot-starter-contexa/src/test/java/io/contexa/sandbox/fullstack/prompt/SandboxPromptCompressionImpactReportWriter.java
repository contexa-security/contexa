package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class SandboxPromptCompressionImpactReportWriter {

    private final ObjectMapper objectMapper;
    private final Path reportDirectory;

    public SandboxPromptCompressionImpactReportWriter(ObjectMapper objectMapper, Path reportDirectory) {
        this.objectMapper = objectMapper;
        this.reportDirectory = reportDirectory;
    }

    public void write(
            String comparisonId,
            SandboxPromptCompressionImpactComparison baseline,
            SandboxPromptCompressionImpactComparison candidate) throws IOException {
        Files.createDirectories(reportDirectory);

        Map<String, Object> baselineSummary = summarizeProfile(baseline);
        Map<String, Object> candidateSummary = summarizeProfile(candidate);
        Map<String, Object> delta = delta(baselineSummary, candidateSummary);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("comparisonId", comparisonId);
        summary.put("generatedAt", Instant.now().toString());
        summary.put("baseline", baselineSummary);
        summary.put("candidate", candidateSummary);
        summary.put("delta", delta);
        summary.put("decisionRegressionPass", Boolean.TRUE.equals(delta.get("decisionRegressionPass")));
        summary.put("compressionGainPass", Boolean.TRUE.equals(delta.get("compressionGainPass")));

        writeJson(reportDirectory.resolve("compression-impact-summary.json"), summary);
        Files.writeString(reportDirectory.resolve("compression-impact-summary.md"), markdown(summary));
        Files.writeString(reportDirectory.resolve("compression-impact-summary.html"), html(summary));
        writeNdjson(reportDirectory.resolve("compression-impact-profiles.ndjson"), List.of(baselineSummary, candidateSummary));
    }

    private Map<String, Object> summarizeProfile(SandboxPromptCompressionImpactComparison comparison) {
        List<PromptExecutionMetadata> metadataList = comparison.promptRunResults().stream()
                .flatMap(run -> run.replayRun().rounds().stream())
                .map(round -> round.snapshot() != null ? round.snapshot().promptExecutionMetadata() : null)
                .filter(java.util.Objects::nonNull)
                .toList();

        double avgRawTotalLength = metadataList.stream().mapToInt(PromptExecutionMetadata::rawTotalPromptLength).average().orElse(0.0d);
        double avgLlmTotalLength = metadataList.stream().mapToInt(PromptExecutionMetadata::totalPromptLength).average().orElse(0.0d);
        double avgSavedEstimatedTokens = metadataList.stream()
                .map(PromptExecutionMetadata::promptCompressionLedger)
                .mapToInt(ledger -> ledger.savedEstimatedTokens())
                .average()
                .orElse(0.0d);
        double compressionAppliedRate = percentage(metadataList.stream()
                .filter(metadata -> metadata.promptCompressionLedger().compressionApplied())
                .count(), metadataList.size());

        Map<String, Object> row = new LinkedHashMap<>();
        row.put("budgetProfile", comparison.budgetProfile());
        row.put("scenarioSelector", comparison.scenarioSelector());
        row.put("roundCount", comparison.roundCount());
        row.put("runCount", comparison.promptRunResults().size());
        row.put("averageRawTotalPromptLength", round(avgRawTotalLength));
        row.put("averageLlmTotalPromptLength", round(avgLlmTotalLength));
        row.put("averageSavedEstimatedTokens", round(avgSavedEstimatedTokens));
        row.put("compressionAppliedRatePercent", round(compressionAppliedRate));
        row.put("cdcMean", metricMean(comparison.decisionRunResults(), SandboxDecisionMetric.CDC.key()));
        row.put("eraMean", metricMean(comparison.decisionRunResults(), SandboxDecisionMetric.ERA.key()));
        row.put("suhrMean", metricMean(comparison.decisionRunResults(), SandboxDecisionMetric.SUHR.key()));
        return row;
    }

    private Map<String, Object> delta(Map<String, Object> baseline, Map<String, Object> candidate) {
        double lengthDelta = number(candidate.get("averageLlmTotalPromptLength")) - number(baseline.get("averageLlmTotalPromptLength"));
        double tokenDelta = number(candidate.get("averageSavedEstimatedTokens")) - number(baseline.get("averageSavedEstimatedTokens"));
        double cdcDelta = number(candidate.get("cdcMean")) - number(baseline.get("cdcMean"));
        double eraDelta = number(candidate.get("eraMean")) - number(baseline.get("eraMean"));
        double suhrDelta = number(candidate.get("suhrMean")) - number(baseline.get("suhrMean"));

        Map<String, Object> delta = new LinkedHashMap<>();
        delta.put("llmTotalPromptLengthDelta", round(lengthDelta));
        delta.put("savedEstimatedTokensDelta", round(tokenDelta));
        delta.put("cdcDelta", round(cdcDelta));
        delta.put("eraDelta", round(eraDelta));
        delta.put("suhrDelta", round(suhrDelta));
        delta.put("compressionGainPass", lengthDelta < 0.0d && tokenDelta >= 0.0d);
        delta.put("decisionRegressionPass", cdcDelta >= -3.0d && eraDelta >= -3.0d && suhrDelta >= -3.0d);
        return delta;
    }

    private String markdown(Map<String, Object> summary) {
        Map<String, Object> baseline = castMap(summary.get("baseline"));
        Map<String, Object> candidate = castMap(summary.get("candidate"));
        Map<String, Object> delta = castMap(summary.get("delta"));
        return String.format(Locale.ROOT, """
                # Prompt Compression Impact

                - comparisonId: `%s`
                - generatedAt: `%s`
                - baselineProfile: `%s`
                - candidateProfile: `%s`
                - compressionGainPass: `%s`
                - decisionRegressionPass: `%s`
                - llmTotalPromptLengthDelta: `%.3f`
                - savedEstimatedTokensDelta: `%.3f`
                - cdcDelta: `%.3f`
                - eraDelta: `%.3f`
                - suhrDelta: `%.3f`
                """,
                summary.get("comparisonId"),
                summary.get("generatedAt"),
                baseline.get("budgetProfile"),
                candidate.get("budgetProfile"),
                delta.get("compressionGainPass"),
                delta.get("decisionRegressionPass"),
                number(delta.get("llmTotalPromptLengthDelta")),
                number(delta.get("savedEstimatedTokensDelta")),
                number(delta.get("cdcDelta")),
                number(delta.get("eraDelta")),
                number(delta.get("suhrDelta")));
    }

    private String html(Map<String, Object> summary) {
        Map<String, Object> baseline = castMap(summary.get("baseline"));
        Map<String, Object> candidate = castMap(summary.get("candidate"));
        Map<String, Object> delta = castMap(summary.get("delta"));
        return """
                <!doctype html><html lang="ko"><head><meta charset="utf-8">
                <title>Prompt Compression Impact</title>
                <style>
                body{font-family:'Segoe UI',sans-serif;margin:32px;color:#1f2937;}
                table{border-collapse:collapse;width:100%%;margin-top:16px;}
                th,td{border:1px solid #d1d5db;padding:8px;text-align:left;}
                th{background:#f3f4f6;}
                </style></head><body>
                <h1>Prompt Compression Impact</h1>
                <p>comparisonId=%s | generatedAt=%s</p>
                <table>
                <thead><tr><th>Profile</th><th>Avg Raw Length</th><th>Avg LLM Length</th><th>Avg Saved Tokens</th><th>CDC</th><th>ERA</th><th>SUHR</th></tr></thead>
                <tbody>
                <tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>
                <tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>
                </tbody></table>
                <h2>Delta</h2>
                <ul>
                <li>llmTotalPromptLengthDelta=%s</li>
                <li>savedEstimatedTokensDelta=%s</li>
                <li>cdcDelta=%s</li>
                <li>eraDelta=%s</li>
                <li>suhrDelta=%s</li>
                <li>compressionGainPass=%s</li>
                <li>decisionRegressionPass=%s</li>
                </ul></body></html>
                """.formatted(
                summary.get("comparisonId"),
                summary.get("generatedAt"),
                baseline.get("budgetProfile"),
                baseline.get("averageRawTotalPromptLength"),
                baseline.get("averageLlmTotalPromptLength"),
                baseline.get("averageSavedEstimatedTokens"),
                baseline.get("cdcMean"),
                baseline.get("eraMean"),
                baseline.get("suhrMean"),
                candidate.get("budgetProfile"),
                candidate.get("averageRawTotalPromptLength"),
                candidate.get("averageLlmTotalPromptLength"),
                candidate.get("averageSavedEstimatedTokens"),
                candidate.get("cdcMean"),
                candidate.get("eraMean"),
                candidate.get("suhrMean"),
                delta.get("llmTotalPromptLengthDelta"),
                delta.get("savedEstimatedTokensDelta"),
                delta.get("cdcDelta"),
                delta.get("eraDelta"),
                delta.get("suhrDelta"),
                delta.get("compressionGainPass"),
                delta.get("decisionRegressionPass"));
    }

    private double metricMean(List<SandboxDecisionBenchmarkRunResult> runResults, String metricKey) {
        return round(runResults.stream()
                .map(run -> run.metrics().get(metricKey))
                .filter(java.util.Objects::nonNull)
                .mapToDouble(Double::doubleValue)
                .average()
                .orElse(0.0d));
    }

    private Map<String, Object> castMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> casted = new LinkedHashMap<>();
            map.forEach((key, entryValue) -> casted.put(String.valueOf(key), entryValue));
            return casted;
        }
        return Map.of();
    }

    private double number(Object value) {
        return value instanceof Number number ? number.doubleValue() : 0.0d;
    }

    private double percentage(long numerator, int denominator) {
        return denominator <= 0 ? 0.0d : (numerator * 100.0d) / denominator;
    }

    private double round(double value) {
        return Math.round(value * 1000.0d) / 1000.0d;
    }

    private void writeJson(Path path, Object payload) throws IOException {
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(path.toFile(), payload);
    }

    private void writeNdjson(Path path, List<Map<String, Object>> rows) throws IOException {
        StringBuilder builder = new StringBuilder();
        for (Map<String, Object> row : rows) {
            builder.append(objectMapper.writeValueAsString(row)).append('\n');
        }
        Files.writeString(path, builder.toString());
    }
}
