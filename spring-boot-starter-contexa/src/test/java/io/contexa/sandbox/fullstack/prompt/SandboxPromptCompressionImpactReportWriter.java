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
        summary.put("reportFiles", Map.of(
                "summaryJson", "compression-impact-summary.json",
                "summaryMd", "compression-impact-summary.md",
                "summaryHtml", "compression-impact-summary.html",
                "profilesNdjson", "compression-impact-profiles.ndjson",
                "runsNdjson", "compression-impact-runs.ndjson",
                "roundsNdjson", "compression-impact-rounds.ndjson"));

        writeJson(reportDirectory.resolve("compression-impact-summary.json"), summary);
        Files.writeString(reportDirectory.resolve("compression-impact-summary.md"), markdown(summary));
        Files.writeString(reportDirectory.resolve("compression-impact-summary.html"), html(summary));
        writeNdjson(reportDirectory.resolve("compression-impact-profiles.ndjson"), List.of(baselineSummary, candidateSummary));
        writeNdjson(reportDirectory.resolve("compression-impact-runs.ndjson"), buildRunRows(baseline, candidate));
        writeNdjson(reportDirectory.resolve("compression-impact-rounds.ndjson"), buildRoundRows(baseline, candidate));
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
        List<SandboxDecisionPerformanceTelemetry> performanceTelemetry = comparison.decisionRunResults().stream()
                .flatMap(run -> run.roundResults().stream())
                .map(SandboxDecisionRoundResult::performanceTelemetry)
                .filter(java.util.Objects::nonNull)
                .toList();

        Map<String, Object> row = new LinkedHashMap<>();
        row.put("budgetProfile", comparison.budgetProfile());
        row.put("profileReportDirectory", profileDirectoryName(comparison.budgetProfile()));
        row.put("scenarioSelector", comparison.scenarioSelector());
        row.put("roundCount", comparison.roundCount());
        row.put("runCount", comparison.promptRunResults().size());
        row.put("averageRawTotalPromptLength", round(avgRawTotalLength));
        row.put("averageLlmTotalPromptLength", round(avgLlmTotalLength));
        row.put("averageSavedEstimatedTokens", round(avgSavedEstimatedTokens));
        row.put("compressionAppliedRatePercent", round(compressionAppliedRate));
        row.put("performanceSampleCount", performanceTelemetry.size());
        row.put("averagePromptPrefillLatencyMs", round(performanceTelemetry.stream()
                .mapToDouble(SandboxDecisionPerformanceTelemetry::promptPrefillLatencyMs)
                .average()
                .orElse(0.0d)));
        row.put("averagePromptEndToEndLatencyMs", round(performanceTelemetry.stream()
                .mapToDouble(SandboxDecisionPerformanceTelemetry::promptEndToEndLatencyMs)
                .average()
                .orElse(0.0d)));
        row.put("averageTokensPerSecond", round(performanceTelemetry.stream()
                .mapToDouble(SandboxDecisionPerformanceTelemetry::tokensPerSecond)
                .average()
                .orElse(0.0d)));
        row.put("averageEstimatedVendorCostRaw", round(performanceTelemetry.stream()
                .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                .filter(java.util.Objects::nonNull)
                .mapToDouble(SandboxDecisionCostEstimate::estimatedVendorCostRaw)
                .average()
                .orElse(0.0d)));
        row.put("averageEstimatedVendorCostLlm", round(performanceTelemetry.stream()
                .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                .filter(java.util.Objects::nonNull)
                .mapToDouble(SandboxDecisionCostEstimate::estimatedVendorCostLlm)
                .average()
                .orElse(0.0d)));
        row.put("averageEstimatedVendorCostSavings", round(performanceTelemetry.stream()
                .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                .filter(java.util.Objects::nonNull)
                .mapToDouble(SandboxDecisionCostEstimate::estimatedVendorCostSavings)
                .average()
                .orElse(0.0d)));
        row.put("cdcMean", metricMean(comparison.decisionRunResults(), SandboxDecisionMetric.CDC.key()));
        row.put("eraMean", metricMean(comparison.decisionRunResults(), SandboxDecisionMetric.ERA.key()));
        row.put("suhrMean", metricMean(comparison.decisionRunResults(), SandboxDecisionMetric.SUHR.key()));
        return row;
    }

    private Map<String, Object> delta(Map<String, Object> baseline, Map<String, Object> candidate) {
        double lengthDelta = number(candidate.get("averageLlmTotalPromptLength")) - number(baseline.get("averageLlmTotalPromptLength"));
        double tokenDelta = number(candidate.get("averageSavedEstimatedTokens")) - number(baseline.get("averageSavedEstimatedTokens"));
        double prefillLatencyDelta = number(candidate.get("averagePromptPrefillLatencyMs")) - number(baseline.get("averagePromptPrefillLatencyMs"));
        double endToEndLatencyDelta = number(candidate.get("averagePromptEndToEndLatencyMs")) - number(baseline.get("averagePromptEndToEndLatencyMs"));
        double tokensPerSecondDelta = number(candidate.get("averageTokensPerSecond")) - number(baseline.get("averageTokensPerSecond"));
        double vendorCostRawDelta = number(candidate.get("averageEstimatedVendorCostRaw")) - number(baseline.get("averageEstimatedVendorCostRaw"));
        double vendorCostLlmDelta = number(candidate.get("averageEstimatedVendorCostLlm")) - number(baseline.get("averageEstimatedVendorCostLlm"));
        double vendorCostSavingsDelta = number(candidate.get("averageEstimatedVendorCostSavings")) - number(baseline.get("averageEstimatedVendorCostSavings"));
        double cdcDelta = number(candidate.get("cdcMean")) - number(baseline.get("cdcMean"));
        double eraDelta = number(candidate.get("eraMean")) - number(baseline.get("eraMean"));
        double suhrDelta = number(candidate.get("suhrMean")) - number(baseline.get("suhrMean"));

        Map<String, Object> delta = new LinkedHashMap<>();
        delta.put("llmTotalPromptLengthDelta", round(lengthDelta));
        delta.put("savedEstimatedTokensDelta", round(tokenDelta));
        delta.put("promptPrefillLatencyDelta", round(prefillLatencyDelta));
        delta.put("promptEndToEndLatencyDelta", round(endToEndLatencyDelta));
        delta.put("tokensPerSecondDelta", round(tokensPerSecondDelta));
        delta.put("estimatedVendorCostRawDelta", round(vendorCostRawDelta));
        delta.put("estimatedVendorCostLlmDelta", round(vendorCostLlmDelta));
        delta.put("estimatedVendorCostSavingsDelta", round(vendorCostSavingsDelta));
        delta.put("cdcDelta", round(cdcDelta));
        delta.put("eraDelta", round(eraDelta));
        delta.put("suhrDelta", round(suhrDelta));
        delta.put("compressionGainPass", lengthDelta < 0.0d && tokenDelta >= 0.0d);
        delta.put("latencyGainPass", prefillLatencyDelta <= 0.0d && endToEndLatencyDelta <= 0.0d);
        delta.put("costGainPass", vendorCostRawDelta <= 0.0d && vendorCostLlmDelta <= 0.0d && vendorCostSavingsDelta >= 0.0d);
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
                - latencyGainPass: `%s`
                - costGainPass: `%s`
                - decisionRegressionPass: `%s`
                - llmTotalPromptLengthDelta: `%.3f`
                - savedEstimatedTokensDelta: `%.3f`
                - promptPrefillLatencyDelta: `%.3f`
                - promptEndToEndLatencyDelta: `%.3f`
                - tokensPerSecondDelta: `%.3f`
                - estimatedVendorCostRawDelta: `%.6f`
                - estimatedVendorCostLlmDelta: `%.6f`
                - estimatedVendorCostSavingsDelta: `%.6f`
                - cdcDelta: `%.3f`
                - eraDelta: `%.3f`
                - suhrDelta: `%.3f`
                - baselineProfileReportDirectory: `%s`
                - candidateProfileReportDirectory: `%s`
                """,
                summary.get("comparisonId"),
                summary.get("generatedAt"),
                baseline.get("budgetProfile"),
                candidate.get("budgetProfile"),
                delta.get("compressionGainPass"),
                delta.get("latencyGainPass"),
                delta.get("costGainPass"),
                delta.get("decisionRegressionPass"),
                number(delta.get("llmTotalPromptLengthDelta")),
                number(delta.get("savedEstimatedTokensDelta")),
                number(delta.get("promptPrefillLatencyDelta")),
                number(delta.get("promptEndToEndLatencyDelta")),
                number(delta.get("tokensPerSecondDelta")),
                number(delta.get("estimatedVendorCostRawDelta")),
                number(delta.get("estimatedVendorCostLlmDelta")),
                number(delta.get("estimatedVendorCostSavingsDelta")),
                number(delta.get("cdcDelta")),
                number(delta.get("eraDelta")),
                number(delta.get("suhrDelta")),
                baseline.get("profileReportDirectory"),
                candidate.get("profileReportDirectory"));
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
                <thead><tr><th>Profile</th><th>Avg Raw Length</th><th>Avg LLM Length</th><th>Avg Saved Tokens</th><th>Prefill ms</th><th>End-to-End ms</th><th>Tokens/sec</th><th>Cost Raw</th><th>Cost LLM</th><th>Savings</th><th>CDC</th><th>ERA</th><th>SUHR</th></tr></thead>
                <tbody>
                <tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>
                <tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>
                </tbody></table>
                <h2>Delta</h2>
                <ul>
                <li>llmTotalPromptLengthDelta=%s</li>
                <li>savedEstimatedTokensDelta=%s</li>
                <li>promptPrefillLatencyDelta=%s</li>
                <li>promptEndToEndLatencyDelta=%s</li>
                <li>tokensPerSecondDelta=%s</li>
                <li>estimatedVendorCostRawDelta=%s</li>
                <li>estimatedVendorCostLlmDelta=%s</li>
                <li>estimatedVendorCostSavingsDelta=%s</li>
                <li>cdcDelta=%s</li>
                <li>eraDelta=%s</li>
                <li>suhrDelta=%s</li>
                <li>compressionGainPass=%s</li>
                <li>latencyGainPass=%s</li>
                <li>costGainPass=%s</li>
                <li>decisionRegressionPass=%s</li>
                </ul>
                <h2>Evidence</h2>
                <ul>
                <li><a href="compression-impact-profiles.ndjson">compression-impact-profiles.ndjson</a></li>
                <li><a href="compression-impact-runs.ndjson">compression-impact-runs.ndjson</a></li>
                <li><a href="compression-impact-rounds.ndjson">compression-impact-rounds.ndjson</a></li>
                <li><a href="%s/decision-summary.html">%s/decision-summary.html</a></li>
                <li><a href="%s/decision-summary.html">%s/decision-summary.html</a></li>
                </ul></body></html>
                """.formatted(
                summary.get("comparisonId"),
                summary.get("generatedAt"),
                baseline.get("budgetProfile"),
                baseline.get("averageRawTotalPromptLength"),
                baseline.get("averageLlmTotalPromptLength"),
                baseline.get("averageSavedEstimatedTokens"),
                baseline.get("averagePromptPrefillLatencyMs"),
                baseline.get("averagePromptEndToEndLatencyMs"),
                baseline.get("averageTokensPerSecond"),
                baseline.get("averageEstimatedVendorCostRaw"),
                baseline.get("averageEstimatedVendorCostLlm"),
                baseline.get("averageEstimatedVendorCostSavings"),
                baseline.get("cdcMean"),
                baseline.get("eraMean"),
                baseline.get("suhrMean"),
                candidate.get("budgetProfile"),
                candidate.get("averageRawTotalPromptLength"),
                candidate.get("averageLlmTotalPromptLength"),
                candidate.get("averageSavedEstimatedTokens"),
                candidate.get("averagePromptPrefillLatencyMs"),
                candidate.get("averagePromptEndToEndLatencyMs"),
                candidate.get("averageTokensPerSecond"),
                candidate.get("averageEstimatedVendorCostRaw"),
                candidate.get("averageEstimatedVendorCostLlm"),
                candidate.get("averageEstimatedVendorCostSavings"),
                candidate.get("cdcMean"),
                candidate.get("eraMean"),
                candidate.get("suhrMean"),
                delta.get("llmTotalPromptLengthDelta"),
                delta.get("savedEstimatedTokensDelta"),
                delta.get("promptPrefillLatencyDelta"),
                delta.get("promptEndToEndLatencyDelta"),
                delta.get("tokensPerSecondDelta"),
                delta.get("estimatedVendorCostRawDelta"),
                delta.get("estimatedVendorCostLlmDelta"),
                delta.get("estimatedVendorCostSavingsDelta"),
                delta.get("cdcDelta"),
                delta.get("eraDelta"),
                delta.get("suhrDelta"),
                delta.get("compressionGainPass"),
                delta.get("latencyGainPass"),
                delta.get("costGainPass"),
                delta.get("decisionRegressionPass"),
                baseline.get("profileReportDirectory"),
                baseline.get("profileReportDirectory"),
                candidate.get("profileReportDirectory"),
                candidate.get("profileReportDirectory"));
    }

    private List<Map<String, Object>> buildRunRows(
            SandboxPromptCompressionImpactComparison baseline,
            SandboxPromptCompressionImpactComparison candidate) {
        return profileEntries(baseline, candidate).stream()
                .flatMap(entry -> entry.comparison().decisionRunResults().stream().map(run -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("comparisonRole", entry.role());
                    row.put("budgetProfile", entry.comparison().budgetProfile());
                    row.put("profileReportDirectory", profileDirectoryName(entry.comparison().budgetProfile()));
                    row.put("benchmarkRunId", run.benchmarkRunId());
                    row.put("username", run.username());
                    row.put("scenarioKey", run.replayRun().scenarioKey());
                    row.put("scenarioFamily", run.replayRun().scenario().scenarioFamily());
                    row.put("roundCount", run.roundResults().size());
                    row.put("CDC", run.metrics().get(SandboxDecisionMetric.CDC.key()));
                    row.put("ERA", run.metrics().get(SandboxDecisionMetric.ERA.key()));
                    row.put("SUHR", run.metrics().get(SandboxDecisionMetric.SUHR.key()));
                    row.put("averagePromptPrefillLatencyMs", round(run.roundResults().stream()
                            .map(SandboxDecisionRoundResult::performanceTelemetry)
                            .filter(java.util.Objects::nonNull)
                            .mapToDouble(SandboxDecisionPerformanceTelemetry::promptPrefillLatencyMs)
                            .average()
                            .orElse(0.0d)));
                    row.put("averagePromptEndToEndLatencyMs", round(run.roundResults().stream()
                            .map(SandboxDecisionRoundResult::performanceTelemetry)
                            .filter(java.util.Objects::nonNull)
                            .mapToDouble(SandboxDecisionPerformanceTelemetry::promptEndToEndLatencyMs)
                            .average()
                            .orElse(0.0d)));
                    row.put("averageEstimatedVendorCostLlm", round(run.roundResults().stream()
                            .map(SandboxDecisionRoundResult::performanceTelemetry)
                            .filter(java.util.Objects::nonNull)
                            .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                            .filter(java.util.Objects::nonNull)
                            .mapToDouble(SandboxDecisionCostEstimate::estimatedVendorCostLlm)
                            .average()
                            .orElse(0.0d)));
                    return row;
                }))
                .toList();
    }

    private List<Map<String, Object>> buildRoundRows(
            SandboxPromptCompressionImpactComparison baseline,
            SandboxPromptCompressionImpactComparison candidate) {
        return profileEntries(baseline, candidate).stream()
                .flatMap(entry -> {
                    Map<String, SandboxDecisionBenchmarkRunResult> decisionRunsById = new LinkedHashMap<>();
                    for (SandboxDecisionBenchmarkRunResult decisionRun : entry.comparison().decisionRunResults()) {
                        decisionRunsById.put(decisionRun.benchmarkRunId(), decisionRun);
                    }
                    return entry.comparison().promptRunResults().stream()
                            .flatMap(promptRun -> promptRun.replayRun().rounds().stream().map(round -> {
                                Map<String, Object> row = new LinkedHashMap<>();
                                row.put("comparisonRole", entry.role());
                                row.put("budgetProfile", entry.comparison().budgetProfile());
                                row.put("profileReportDirectory", profileDirectoryName(entry.comparison().budgetProfile()));
                                row.put("benchmarkRunId", promptRun.benchmarkRunId());
                                row.put("username", promptRun.username());
                                row.put("scenarioKey", promptRun.replayRun().scenarioKey());
                                row.put("scenarioFamily", promptRun.replayRun().scenario().scenarioFamily());
                                row.put("roundNumber", round.roundNumber());
                                row.put("roundKey", round.roundPlan().roundKey());
                                if (round.snapshot() != null && round.snapshot().promptExecutionMetadata() != null) {
                                    PromptExecutionMetadata metadata = round.snapshot().promptExecutionMetadata();
                                    row.put("promptTransformationMode", metadata.promptCompressionLedger().transformationMode());
                                    row.put("rawTotalPromptLength", metadata.rawTotalPromptLength());
                                    row.put("llmTotalPromptLength", metadata.totalPromptLength());
                                    row.put("savedEstimatedTokens", metadata.promptCompressionLedger().savedEstimatedTokens());
                                }
                                SandboxDecisionBenchmarkRunResult decisionRun = decisionRunsById.get(promptRun.benchmarkRunId());
                                SandboxDecisionRoundResult decisionRound = decisionRun == null
                                        ? null
                                        : decisionRun.roundResults().stream()
                                        .filter(candidateRound -> candidateRound.roundNumber() == round.roundNumber())
                                        .findFirst()
                                        .orElse(null);
                                if (decisionRound != null) {
                                    row.put("CDC", decisionRound.cdcScore());
                                    row.put("ERA", decisionRound.eraScore());
                                    row.put("SUHR", decisionRound.suhrScore());
                                    appendPerformanceTelemetry(row, decisionRound.performanceTelemetry());
                                }
                                return row;
                            }));
                })
                .toList();
    }

    private void appendPerformanceTelemetry(
            Map<String, Object> row,
            SandboxDecisionPerformanceTelemetry telemetry) {
        if (telemetry == null) {
            return;
        }
        row.put("promptPrefillLatencyMs", telemetry.promptPrefillLatencyMs());
        row.put("promptEndToEndLatencyMs", telemetry.promptEndToEndLatencyMs());
        row.put("tokensPerSecond", telemetry.tokensPerSecond());
        row.put("estimatedOutputTokens", telemetry.estimatedOutputTokens());
        if (telemetry.costEstimate() != null) {
            row.put("estimatedVendorCostRaw", telemetry.costEstimate().estimatedVendorCostRaw());
            row.put("estimatedVendorCostLlm", telemetry.costEstimate().estimatedVendorCostLlm());
            row.put("estimatedVendorCostSavings", telemetry.costEstimate().estimatedVendorCostSavings());
        }
    }

    private List<ProfileEntry> profileEntries(
            SandboxPromptCompressionImpactComparison baseline,
            SandboxPromptCompressionImpactComparison candidate) {
        return List.of(new ProfileEntry("baseline", baseline), new ProfileEntry("candidate", candidate));
    }

    private String profileDirectoryName(String budgetProfile) {
        return SandboxPromptCompressionImpactBenchmarkRunner.profileDirectoryName(budgetProfile);
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

    private record ProfileEntry(String role, SandboxPromptCompressionImpactComparison comparison) {
    }
}
