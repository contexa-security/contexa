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
        writeNdjson(reportDirectory.resolve("compression-impact-runs.ndjson"), buildRunRows(List.of(baseline, candidate)));
        writeNdjson(reportDirectory.resolve("compression-impact-rounds.ndjson"), buildRoundRows(List.of(baseline, candidate)));
    }

    public void writeMatrix(
            String matrixId,
            List<SandboxPromptCompressionImpactComparison> comparisons,
            String baselineProfile) throws IOException {
        Files.createDirectories(reportDirectory);
        List<SandboxPromptCompressionImpactComparison> safeComparisons = comparisons == null ? List.of() : comparisons;
        List<Map<String, Object>> profileSummaries = safeComparisons.stream()
                .map(this::summarizeProfile)
                .toList();
        writeJson(reportDirectory.resolve("compression-performance-summary.json"),
                buildCompressionPerformanceSummary(matrixId, baselineProfile, profileSummaries));
        Files.writeString(
                reportDirectory.resolve("compression-performance-summary.md"),
                compressionPerformanceMarkdown(matrixId, baselineProfile, profileSummaries));
        Files.writeString(
                reportDirectory.resolve("compression-performance-summary.html"),
                compressionPerformanceHtml(matrixId, baselineProfile, profileSummaries));
        writeNdjson(reportDirectory.resolve("compression-performance-rounds.ndjson"), buildRoundRows(safeComparisons));

        writeJson(reportDirectory.resolve("profile-comparison-summary.json"),
                buildProfileComparisonSummary(matrixId, baselineProfile, profileSummaries));
        Files.writeString(
                reportDirectory.resolve("profile-comparison-summary.html"),
                profileComparisonHtml(matrixId, baselineProfile, profileSummaries));
        writeNdjson(reportDirectory.resolve("profile-comparison-rounds.ndjson"),
                buildProfileComparisonRoundRows(baselineProfile, safeComparisons));
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
        SandboxDecisionCostProfile costProfile = performanceTelemetry.stream()
                .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                .filter(java.util.Objects::nonNull)
                .map(SandboxDecisionCostEstimate::costProfile)
                .filter(java.util.Objects::nonNull)
                .findFirst()
                .orElse(new SandboxDecisionCostProfile(
                        "UNCONFIGURED",
                        "Unconfigured reference pricing",
                        "USD",
                        0.0d,
                        0.0d,
                        0.0d,
                        false));

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
        row.put("prefillMeasuredRatePercent", round(percentage(performanceTelemetry.stream()
                .filter(SandboxDecisionPerformanceTelemetry::prefillMeasured)
                .count(), performanceTelemetry.size())));
        row.put("averagePromptPrefillLatencyMs", round(performanceTelemetry.stream()
                .filter(SandboxDecisionPerformanceTelemetry::prefillMeasured)
                .mapToDouble(SandboxDecisionPerformanceTelemetry::promptPrefillLatencyMs)
                .average()
                .orElse(0.0d)));
        row.put("averagePromptEndToEndLatencyMs", round(performanceTelemetry.stream()
                .mapToDouble(SandboxDecisionPerformanceTelemetry::promptEndToEndLatencyMs)
                .average()
                .orElse(0.0d)));
        row.put("averageEstimatedOutputTokens", round(performanceTelemetry.stream()
                .mapToDouble(SandboxDecisionPerformanceTelemetry::estimatedOutputTokens)
                .average()
                .orElse(0.0d)));
        row.put("averageTokensPerSecond", round(performanceTelemetry.stream()
                .mapToDouble(SandboxDecisionPerformanceTelemetry::tokensPerSecond)
                .average()
                .orElse(0.0d)));
        row.put("averageLlmInvocationCount", round(performanceTelemetry.stream()
                .mapToDouble(SandboxDecisionPerformanceTelemetry::llmInvocationCount)
                .average()
                .orElse(0.0d)));
        row.put("repairAttemptRatePercent", round(percentage(performanceTelemetry.stream()
                .filter(SandboxDecisionPerformanceTelemetry::repairAttempted)
                .count(), performanceTelemetry.size())));
        row.put("repairSucceededRatePercent", round(percentage(performanceTelemetry.stream()
                .filter(SandboxDecisionPerformanceTelemetry::repairSucceeded)
                .count(), performanceTelemetry.size())));
        row.put("structuredSucceededRatePercent", round(percentage(performanceTelemetry.stream()
                .filter(SandboxDecisionPerformanceTelemetry::structuredSucceeded)
                .count(), performanceTelemetry.size())));
        row.put("averageEstimatedVendorCostRaw", roundCost(performanceTelemetry.stream()
                .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                .filter(java.util.Objects::nonNull)
                .mapToDouble(SandboxDecisionCostEstimate::estimatedVendorCostRaw)
                .average()
                .orElse(0.0d)));
        row.put("averageEstimatedVendorCostLlm", roundCost(performanceTelemetry.stream()
                .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                .filter(java.util.Objects::nonNull)
                .mapToDouble(SandboxDecisionCostEstimate::estimatedVendorCostLlm)
                .average()
                .orElse(0.0d)));
        row.put("averageEstimatedVendorCostSavings", roundCost(performanceTelemetry.stream()
                .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                .filter(java.util.Objects::nonNull)
                .mapToDouble(SandboxDecisionCostEstimate::estimatedVendorCostSavings)
                .average()
                .orElse(0.0d)));
        row.put("averageEstimatedInfrastructureCostRaw", roundCost(performanceTelemetry.stream()
                .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                .filter(java.util.Objects::nonNull)
                .mapToDouble(SandboxDecisionCostEstimate::estimatedInfrastructureCostRaw)
                .average()
                .orElse(0.0d)));
        row.put("averageEstimatedInfrastructureCostLlm", roundCost(performanceTelemetry.stream()
                .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                .filter(java.util.Objects::nonNull)
                .mapToDouble(SandboxDecisionCostEstimate::estimatedInfrastructureCostLlm)
                .average()
                .orElse(0.0d)));
        row.put("averageEstimatedInfrastructureCostSavings", roundCost(performanceTelemetry.stream()
                .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                .filter(java.util.Objects::nonNull)
                .mapToDouble(SandboxDecisionCostEstimate::estimatedInfrastructureCostSavings)
                .average()
                .orElse(0.0d)));
        row.put("costProfileKey", costProfile.profileKey());
        row.put("costProfileDisplayName", costProfile.displayName());
        row.put("costCurrencyCode", costProfile.currencyCode());
        row.put("costProfileInfrastructurePerHour", costProfile.infrastructureCostPerHour());
        row.put("costProfileConfigured", costProfile.configured());
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
        double infrastructureCostRawDelta = number(candidate.get("averageEstimatedInfrastructureCostRaw")) - number(baseline.get("averageEstimatedInfrastructureCostRaw"));
        double infrastructureCostLlmDelta = number(candidate.get("averageEstimatedInfrastructureCostLlm")) - number(baseline.get("averageEstimatedInfrastructureCostLlm"));
        double infrastructureCostSavingsDelta = number(candidate.get("averageEstimatedInfrastructureCostSavings")) - number(baseline.get("averageEstimatedInfrastructureCostSavings"));
        double cdcDelta = number(candidate.get("cdcMean")) - number(baseline.get("cdcMean"));
        double eraDelta = number(candidate.get("eraMean")) - number(baseline.get("eraMean"));
        double suhrDelta = number(candidate.get("suhrMean")) - number(baseline.get("suhrMean"));
        boolean costEvaluable = booleanValue(baseline.get("costProfileConfigured"))
                && booleanValue(candidate.get("costProfileConfigured"));

        Map<String, Object> delta = new LinkedHashMap<>();
        delta.put("llmTotalPromptLengthDelta", round(lengthDelta));
        delta.put("savedEstimatedTokensDelta", round(tokenDelta));
        delta.put("promptPrefillLatencyDelta", round(prefillLatencyDelta));
        delta.put("promptEndToEndLatencyDelta", round(endToEndLatencyDelta));
        delta.put("tokensPerSecondDelta", round(tokensPerSecondDelta));
        delta.put("estimatedVendorCostRawDelta", roundCost(vendorCostRawDelta));
        delta.put("estimatedVendorCostLlmDelta", roundCost(vendorCostLlmDelta));
        delta.put("estimatedVendorCostSavingsDelta", roundCost(vendorCostSavingsDelta));
        delta.put("estimatedInfrastructureCostRawDelta", roundCost(infrastructureCostRawDelta));
        delta.put("estimatedInfrastructureCostLlmDelta", roundCost(infrastructureCostLlmDelta));
        delta.put("estimatedInfrastructureCostSavingsDelta", roundCost(infrastructureCostSavingsDelta));
        delta.put("cdcDelta", round(cdcDelta));
        delta.put("eraDelta", round(eraDelta));
        delta.put("suhrDelta", round(suhrDelta));
        delta.put("compressionGainPass", lengthDelta < 0.0d && tokenDelta >= 0.0d);
        delta.put("latencyGainPass", endToEndLatencyDelta <= 0.0d);
        delta.put("costGainEvaluable", costEvaluable);
        delta.put("costGainPass",
                costEvaluable
                        && (vendorCostRawDelta <= 0.0d && vendorCostLlmDelta <= 0.0d && vendorCostSavingsDelta >= 0.0d)
                        && (infrastructureCostRawDelta <= 0.0d
                        && infrastructureCostLlmDelta <= 0.0d
                        && infrastructureCostSavingsDelta >= 0.0d));
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
                - costGainEvaluable: `%s`
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
                - estimatedInfrastructureCostRawDelta: `%.6f`
                - estimatedInfrastructureCostLlmDelta: `%.6f`
                - estimatedInfrastructureCostSavingsDelta: `%.6f`
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
                delta.get("costGainEvaluable"),
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
                number(delta.get("estimatedInfrastructureCostRawDelta")),
                number(delta.get("estimatedInfrastructureCostLlmDelta")),
                number(delta.get("estimatedInfrastructureCostSavingsDelta")),
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
                <li>estimatedInfrastructureCostRawDelta=%s</li>
                <li>estimatedInfrastructureCostLlmDelta=%s</li>
                <li>estimatedInfrastructureCostSavingsDelta=%s</li>
                <li>cdcDelta=%s</li>
                <li>eraDelta=%s</li>
                <li>suhrDelta=%s</li>
                <li>compressionGainPass=%s</li>
                <li>latencyGainPass=%s</li>
                <li>costGainEvaluable=%s</li>
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
                delta.get("estimatedInfrastructureCostRawDelta"),
                delta.get("estimatedInfrastructureCostLlmDelta"),
                delta.get("estimatedInfrastructureCostSavingsDelta"),
                delta.get("cdcDelta"),
                delta.get("eraDelta"),
                delta.get("suhrDelta"),
                delta.get("compressionGainPass"),
                delta.get("latencyGainPass"),
                delta.get("costGainEvaluable"),
                delta.get("costGainPass"),
                delta.get("decisionRegressionPass"),
                baseline.get("profileReportDirectory"),
                baseline.get("profileReportDirectory"),
                candidate.get("profileReportDirectory"),
                candidate.get("profileReportDirectory"));
    }

    private List<Map<String, Object>> buildRunRows(List<SandboxPromptCompressionImpactComparison> comparisons) {
        return comparisons.stream()
                .flatMap(comparison -> comparison.decisionRunResults().stream().map(run -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("budgetProfile", comparison.budgetProfile());
                    row.put("profileReportDirectory", profileDirectoryName(comparison.budgetProfile()));
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
                    row.put("averageEstimatedVendorCostLlm", roundCost(run.roundResults().stream()
                            .map(SandboxDecisionRoundResult::performanceTelemetry)
                            .filter(java.util.Objects::nonNull)
                            .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                            .filter(java.util.Objects::nonNull)
                            .mapToDouble(SandboxDecisionCostEstimate::estimatedVendorCostLlm)
                            .average()
                            .orElse(0.0d)));
                    row.put("averageEstimatedInfrastructureCostLlm", roundCost(run.roundResults().stream()
                            .map(SandboxDecisionRoundResult::performanceTelemetry)
                            .filter(java.util.Objects::nonNull)
                            .map(SandboxDecisionPerformanceTelemetry::costEstimate)
                            .filter(java.util.Objects::nonNull)
                            .mapToDouble(SandboxDecisionCostEstimate::estimatedInfrastructureCostLlm)
                            .average()
                            .orElse(0.0d)));
                    return row;
                }))
                .toList();
    }

    private List<Map<String, Object>> buildRoundRows(List<SandboxPromptCompressionImpactComparison> comparisons) {
        return comparisons.stream()
                .flatMap(comparison -> {
                    Map<String, SandboxDecisionBenchmarkRunResult> decisionRunsById = new LinkedHashMap<>();
                    for (SandboxDecisionBenchmarkRunResult decisionRun : comparison.decisionRunResults()) {
                        decisionRunsById.put(decisionRun.benchmarkRunId(), decisionRun);
                    }
                    return comparison.promptRunResults().stream()
                            .flatMap(promptRun -> promptRun.replayRun().rounds().stream().map(round -> {
                                Map<String, Object> row = new LinkedHashMap<>();
                                row.put("budgetProfile", comparison.budgetProfile());
                                row.put("profileReportDirectory", profileDirectoryName(comparison.budgetProfile()));
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

    private void appendPerformanceTelemetry(Map<String, Object> row, SandboxDecisionPerformanceTelemetry telemetry) {
        if (telemetry == null) {
            return;
        }
        row.put("promptPrefillLatencyMs", telemetry.promptPrefillLatencyMs());
        row.put("promptEndToEndLatencyMs", telemetry.promptEndToEndLatencyMs());
        row.put("prefillMeasured", telemetry.prefillMeasured());
        row.put("tokensPerSecond", telemetry.tokensPerSecond());
        row.put("estimatedOutputTokens", telemetry.estimatedOutputTokens());
        row.put("llmInvocationCount", telemetry.llmInvocationCount());
        row.put("structuredAttempted", telemetry.structuredAttempted());
        row.put("structuredSucceeded", telemetry.structuredSucceeded());
        row.put("repairAttempted", telemetry.repairAttempted());
        row.put("repairSucceeded", telemetry.repairSucceeded());
        if (telemetry.costEstimate() != null) {
            row.put("estimatedVendorCostRaw", telemetry.costEstimate().estimatedVendorCostRaw());
            row.put("estimatedVendorCostLlm", telemetry.costEstimate().estimatedVendorCostLlm());
            row.put("estimatedVendorCostSavings", telemetry.costEstimate().estimatedVendorCostSavings());
            row.put("estimatedInfrastructureCostRaw", telemetry.costEstimate().estimatedInfrastructureCostRaw());
            row.put("estimatedInfrastructureCostLlm", telemetry.costEstimate().estimatedInfrastructureCostLlm());
            row.put("estimatedInfrastructureCostSavings", telemetry.costEstimate().estimatedInfrastructureCostSavings());
        }
    }

    private String profileDirectoryName(String budgetProfile) {
        return SandboxPromptCompressionImpactBenchmarkRunner.profileDirectoryName(budgetProfile);
    }

    private Map<String, Object> buildCompressionPerformanceSummary(
            String matrixId,
            String baselineProfile,
            List<Map<String, Object>> profileSummaries) {
        Map<String, Object> baselineSummary = resolveBaselineSummary(baselineProfile, profileSummaries);
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("matrixId", matrixId);
        summary.put("generatedAt", Instant.now().toString());
        summary.put("baselineProfile", baselineSummary.get("budgetProfile"));
        summary.put("profiles", profileSummaries.stream()
                .map(row -> compressionPerformanceProfileRow(baselineSummary, row))
                .toList());
        summary.put("reportFiles", Map.of(
                "summaryJson", "compression-performance-summary.json",
                "summaryMd", "compression-performance-summary.md",
                "summaryHtml", "compression-performance-summary.html",
                "roundsNdjson", "compression-performance-rounds.ndjson"));
        return summary;
    }

    private Map<String, Object> compressionPerformanceProfileRow(
            Map<String, Object> baselineSummary,
            Map<String, Object> summaryRow) {
        String profile = String.valueOf(summaryRow.get("budgetProfile"));
        double tokenGainPercent = computeGainPercent(
                number(summaryRow.get("averageRawTotalPromptLength")),
                number(summaryRow.get("averageLlmTotalPromptLength")));
        double prefillGainPercent = computeGainPercent(
                number(baselineSummary.get("averagePromptPrefillLatencyMs")),
                number(summaryRow.get("averagePromptPrefillLatencyMs")));
        double latencyGainPercent = computeGainPercent(
                number(baselineSummary.get("averagePromptEndToEndLatencyMs")),
                number(summaryRow.get("averagePromptEndToEndLatencyMs")));
        double vendorCostGainPercent = computeGainPercent(
                number(baselineSummary.get("averageEstimatedVendorCostLlm")),
                number(summaryRow.get("averageEstimatedVendorCostLlm")));
        double infrastructureCostGainPercent = computeGainPercent(
                number(baselineSummary.get("averageEstimatedInfrastructureCostLlm")),
                number(summaryRow.get("averageEstimatedInfrastructureCostLlm")));
        Map<String, Object> row = new LinkedHashMap<>(summaryRow);
        row.put("tokenGainPercent", round(tokenGainPercent));
        row.put("prefillGainPercent", round(prefillGainPercent));
        row.put("latencyGainPercent", round(latencyGainPercent));
        row.put("vendorCostGainPercent", round(vendorCostGainPercent));
        row.put("infrastructureCostGainPercent", round(infrastructureCostGainPercent));
        row.put("minimumTokenGainPercent", requiredTokenGainPercent(profile));
        row.put("minimumLatencyGainPercent", requiredLatencyGainPercent(profile));
        row.put("qualityPass", qualityPass(summaryRow));
        row.put("performanceGatePass", tokenGainPercent >= requiredTokenGainPercent(profile));
        row.put("costGatePass",
                booleanValue(summaryRow.get("costProfileConfigured"))
                        && vendorCostGainPercent >= 0.0d
                        && infrastructureCostGainPercent >= 0.0d);
        row.put("costGateEvaluable", booleanValue(summaryRow.get("costProfileConfigured")));
        row.put("latencyGatePass", latencyGainPercent >= requiredLatencyGainPercent(profile));
        return row;
    }

    private String compressionPerformanceMarkdown(
            String matrixId,
            String baselineProfile,
            List<Map<String, Object>> profileSummaries) {
        StringBuilder builder = new StringBuilder();
        Map<String, Object> baselineSummary = resolveBaselineSummary(baselineProfile, profileSummaries);
        builder.append("# Compression Performance Summary\n\n")
                .append("- matrixId: `").append(matrixId).append("`\n")
                .append("- baselineProfile: `").append(baselineSummary.get("budgetProfile")).append("`\n\n");
        for (Map<String, Object> row : profileSummaries.stream()
                .map(summaryRow -> compressionPerformanceProfileRow(baselineSummary, summaryRow))
                .toList()) {
            builder.append("## ").append(row.get("budgetProfile")).append("\n\n")
                    .append("- tokenGainPercent: `").append(row.get("tokenGainPercent")).append("`\n")
                    .append("- latencyGainPercent: `").append(row.get("latencyGainPercent")).append("`\n")
                    .append("- minimumTokenGainPercent: `").append(row.get("minimumTokenGainPercent")).append("`\n")
                    .append("- minimumLatencyGainPercent: `").append(row.get("minimumLatencyGainPercent")).append("`\n")
                    .append("- performanceGatePass: `").append(row.get("performanceGatePass")).append("`\n")
                    .append("- latencyGatePass: `").append(row.get("latencyGatePass")).append("`\n")
                    .append("- costGateEvaluable: `").append(row.get("costGateEvaluable")).append("`\n")
                    .append("- costGatePass: `").append(row.get("costGatePass")).append("`\n")
                    .append("- qualityPass: `").append(row.get("qualityPass")).append("`\n\n");
        }
        return builder.toString();
    }

    private String compressionPerformanceHtml(
            String matrixId,
            String baselineProfile,
            List<Map<String, Object>> profileSummaries) {
        Map<String, Object> baselineSummary = resolveBaselineSummary(baselineProfile, profileSummaries);
        String rows = profileSummaries.stream()
                .map(summaryRow -> compressionPerformanceProfileRow(baselineSummary, summaryRow))
                .map(row -> "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>".formatted(
                        row.get("budgetProfile"),
                        row.get("tokenGainPercent"),
                        row.get("prefillGainPercent"),
                        row.get("latencyGainPercent"),
                        row.get("minimumTokenGainPercent"),
                        row.get("minimumLatencyGainPercent"),
                        row.get("performanceGatePass"),
                        row.get("latencyGatePass"),
                        row.get("costGatePass"),
                        row.get("qualityPass")))
                .reduce("", String::concat);
        return """
                <!doctype html><html lang="ko"><head><meta charset="utf-8">
                <title>Compression Performance Summary</title>
                <style>body{font-family:'Segoe UI',sans-serif;margin:32px;color:#1f2937;}table{border-collapse:collapse;width:100%%;}th,td{border:1px solid #d1d5db;padding:8px;text-align:left;}th{background:#f3f4f6;}</style>
                </head><body>
                <h1>Compression Performance Summary</h1>
                <p>matrixId=%s | baselineProfile=%s</p>
                <table><thead><tr><th>Profile</th><th>Token Gain %%</th><th>Prefill Gain %%</th><th>End-to-End Gain %%</th><th>Required Token Gain %%</th><th>Required End-to-End Gain %%</th><th>Performance Gate</th><th>Latency Gate</th><th>Cost Gate</th><th>Quality Gate</th></tr></thead><tbody>%s</tbody></table>
                <p><a href="compression-performance-rounds.ndjson">compression-performance-rounds.ndjson</a></p>
                </body></html>
                """.formatted(matrixId, baselineSummary.get("budgetProfile"), rows);
    }

    private Map<String, Object> buildProfileComparisonSummary(
            String matrixId,
            String baselineProfile,
            List<Map<String, Object>> profileSummaries) {
        Map<String, Object> baseline = resolveBaselineSummary(baselineProfile, profileSummaries);
        List<Map<String, Object>> comparisons = profileSummaries.stream()
                .filter(row -> !String.valueOf(row.get("budgetProfile")).equals(String.valueOf(baseline.get("budgetProfile"))))
                .map(row -> comparisonAgainstBaseline(baseline, row))
                .toList();
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("matrixId", matrixId);
        summary.put("generatedAt", Instant.now().toString());
        summary.put("baselineProfile", baseline.get("budgetProfile"));
        summary.put("comparisons", comparisons);
        summary.put("reportFiles", Map.of(
                "summaryJson", "profile-comparison-summary.json",
                "summaryHtml", "profile-comparison-summary.html",
                "roundsNdjson", "profile-comparison-rounds.ndjson"));
        return summary;
    }

    private String profileComparisonHtml(
            String matrixId,
            String baselineProfile,
            List<Map<String, Object>> profileSummaries) {
        Map<String, Object> summary = buildProfileComparisonSummary(matrixId, baselineProfile, profileSummaries);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> comparisons = (List<Map<String, Object>>) summary.get("comparisons");
        String rows = comparisons.stream()
                .map(row -> "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>".formatted(
                        row.get("candidateProfile"),
                        row.get("llmTotalPromptLengthDelta"),
                        row.get("promptPrefillLatencyDelta"),
                        row.get("estimatedInfrastructureCostLlmDelta"),
                        row.get("decisionRegressionPass")))
                .reduce("", String::concat);
        return """
                <!doctype html><html lang="ko"><head><meta charset="utf-8">
                <title>Profile Comparison Summary</title>
                <style>body{font-family:'Segoe UI',sans-serif;margin:32px;color:#1f2937;}table{border-collapse:collapse;width:100%%;}th,td{border:1px solid #d1d5db;padding:8px;text-align:left;}th{background:#f3f4f6;}</style>
                </head><body>
                <h1>Profile Comparison Summary</h1>
                <p>matrixId=%s | baselineProfile=%s</p>
                <table><thead><tr><th>Candidate</th><th>LLM Length Delta</th><th>Prefill Delta</th><th>Infrastructure Cost Delta</th><th>Decision Regression Pass</th></tr></thead><tbody>%s</tbody></table>
                <p><a href="profile-comparison-rounds.ndjson">profile-comparison-rounds.ndjson</a></p>
                </body></html>
                """.formatted(matrixId, baselineProfile, rows);
    }

    private List<Map<String, Object>> buildProfileComparisonRoundRows(
            String baselineProfile,
            List<SandboxPromptCompressionImpactComparison> comparisons) {
        Map<String, SandboxPromptCompressionImpactComparison> byProfile = comparisons.stream()
                .collect(java.util.stream.Collectors.toMap(
                        SandboxPromptCompressionImpactComparison::budgetProfile,
                        comparison -> comparison,
                        (left, right) -> left,
                        LinkedHashMap::new));
        SandboxPromptCompressionImpactComparison baseline = byProfile.getOrDefault(
                baselineProfile,
                comparisons.isEmpty() ? null : comparisons.getFirst());
        if (baseline == null) {
            return List.of();
        }
        return comparisons.stream()
                .filter(comparison -> !comparison.budgetProfile().equals(baseline.budgetProfile()))
                .flatMap(comparison -> comparison.decisionRunResults().stream()
                        .flatMap(run -> run.roundResults().stream().map(round -> {
                            Map<String, Object> row = new LinkedHashMap<>();
                            row.put("baselineProfile", baseline.budgetProfile());
                            row.put("candidateProfile", comparison.budgetProfile());
                            row.put("benchmarkRunId", run.benchmarkRunId());
                            row.put("roundNumber", round.roundNumber());
                            row.put("CDC", round.cdcScore());
                            row.put("ERA", round.eraScore());
                            row.put("SUHR", round.suhrScore());
                            appendPerformanceTelemetry(row, round.performanceTelemetry());
                            return row;
                        })))
                .toList();
    }

    private Map<String, Object> comparisonAgainstBaseline(Map<String, Object> baseline, Map<String, Object> candidate) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("baselineProfile", baseline.get("budgetProfile"));
        row.put("candidateProfile", candidate.get("budgetProfile"));
        row.putAll(delta(baseline, candidate));
        return row;
    }

    private Map<String, Object> resolveBaselineSummary(
            String baselineProfile,
            List<Map<String, Object>> profileSummaries) {
        return profileSummaries.stream()
                .filter(row -> baselineProfile.equals(String.valueOf(row.get("budgetProfile"))))
                .findFirst()
                .orElse(profileSummaries.isEmpty() ? Map.of() : profileSummaries.getFirst());
    }

    private boolean qualityPass(Map<String, Object> summaryRow) {
        return number(summaryRow.get("cdcMean")) >= 95.0d
                && number(summaryRow.get("eraMean")) >= 95.0d
                && number(summaryRow.get("suhrMean")) >= 95.0d;
    }

    private double requiredTokenGainPercent(String budgetProfile) {
        return switch (String.valueOf(budgetProfile)) {
            case "CORTEX_L1_STANDARD" -> 5.0d;
            case "CORTEX_L1_COMPACT" -> 15.0d;
            case "CORTEX_L1_DECISION_COMPACT" -> 20.0d;
            default -> 0.0d;
        };
    }

    private double requiredLatencyGainPercent(String budgetProfile) {
        return switch (String.valueOf(budgetProfile)) {
            case "CORTEX_L1_STANDARD" -> 3.0d;
            case "CORTEX_L1_COMPACT" -> 8.0d;
            case "CORTEX_L1_DECISION_COMPACT" -> 10.0d;
            default -> 0.0d;
        };
    }

    private double computeGainPercent(double baselineValue, double candidateValue) {
        if (baselineValue <= 0.0d) {
            return 0.0d;
        }
        return ((baselineValue - candidateValue) / baselineValue) * 100.0d;
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

    private boolean booleanValue(Object value) {
        return value instanceof Boolean bool && bool;
    }

    private double percentage(long numerator, int denominator) {
        return denominator <= 0 ? 0.0d : (numerator * 100.0d) / denominator;
    }

    private double round(double value) {
        return Math.round(value * 1000.0d) / 1000.0d;
    }

    private double roundCost(double value) {
        return Math.round(value * 1_000_000.0d) / 1_000_000.0d;
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
