package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptCompressionLedger;
import io.contexa.contexacore.std.components.prompt.PromptCompressionRecord;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Writes raw-vs-LLM prompt compression evidence separately from the main prompt benchmark summary.
 *
 * The evidence bundle is submission-oriented:
 * - round-level raw/llm prompt lengths and savings
 * - run-level savings and profile usage
 * - prompt budget profile ledger for compact-vs-standard replay comparison
 */
public final class SandboxPromptCompressionEvidenceWriter {

    private final ObjectMapper objectMapper;
    private final Path reportDirectory;

    public SandboxPromptCompressionEvidenceWriter(ObjectMapper objectMapper, Path reportDirectory) {
        this.objectMapper = objectMapper;
        this.reportDirectory = reportDirectory;
    }

    public void write(List<SandboxPromptBenchmarkRunResult> runResults) throws IOException {
        Files.createDirectories(reportDirectory);

        List<Map<String, Object>> roundRows = buildRoundRows(runResults);
        List<Map<String, Object>> runRows = buildRunRows(runResults);
        List<Map<String, Object>> profileRows = buildProfileLedger(roundRows);
        Map<String, Object> summary = buildSummary(runResults, roundRows, runRows, profileRows);

        Files.writeString(
                reportDirectory.resolve("compression-summary.json"),
                objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(summary));
        Files.writeString(
                reportDirectory.resolve("compression-summary.md"),
                buildMarkdown(summary, profileRows));
        Files.writeString(
                reportDirectory.resolve("compression-summary.html"),
                buildHtml(summary, profileRows));
        writeNdjson(reportDirectory.resolve("compression-runs.ndjson"), runRows);
        writeNdjson(reportDirectory.resolve("compression-rounds.ndjson"), roundRows);
        writeNdjson(reportDirectory.resolve("prompt-profile-ledger.ndjson"), profileRows);
    }

    private Map<String, Object> buildSummary(
            List<SandboxPromptBenchmarkRunResult> runResults,
            List<Map<String, Object>> roundRows,
            List<Map<String, Object>> runRows,
            List<Map<String, Object>> profileRows) {
        double averageSavedCharacters = average(roundRows, "savedCharacters");
        double averageSavedEstimatedTokens = average(roundRows, "savedEstimatedTokens");
        long compressionAppliedRoundCount = countTrue(roundRows, "compressionApplied");
        long rawParityRoundCount = countTrue(roundRows, "rawPromptParity");
        long compactProfileRoundCount = roundRows.stream()
                .filter(row -> "COMPACT".equals(String.valueOf(row.get("budgetViewProfile"))))
                .count();

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("generatedAt", Instant.now().toString());
        summary.put("runCount", runResults.size());
        summary.put("roundCount", roundRows.size());
        summary.put("runLedgerCount", runRows.size());
        summary.put("profileLedgerCount", profileRows.size());
        summary.put("averageSavedCharacters", averageSavedCharacters);
        summary.put("averageSavedEstimatedTokens", averageSavedEstimatedTokens);
        summary.put("compressionAppliedRoundCount", compressionAppliedRoundCount);
        summary.put("compressionAppliedRatePercent", percentage(compressionAppliedRoundCount, roundRows.size()));
        summary.put("rawPromptParityRoundCount", rawParityRoundCount);
        summary.put("rawPromptParityRatePercent", percentage(rawParityRoundCount, roundRows.size()));
        summary.put("compactProfileRoundCount", compactProfileRoundCount);
        summary.put("observedBudgetProfiles", profileRows.stream().map(row -> row.get("budgetProfile")).toList());
        summary.put("observedTransformationModes", roundRows.stream()
                .map(row -> String.valueOf(row.get("promptTransformationMode")))
                .distinct()
                .sorted()
                .toList());
        summary.put("scopeOperationHistogram", buildScopeOperationHistogram(roundRows));
        summary.put("promptProfileLedger", profileRows);
        return summary;
    }

    private List<Map<String, Object>> buildRunRows(List<SandboxPromptBenchmarkRunResult> runResults) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (SandboxPromptBenchmarkRunResult runResult : runResults) {
            List<PromptExecutionMetadata> metadataList = runResult.replayRun().rounds().stream()
                    .map(round -> round.snapshot() != null ? round.snapshot().promptExecutionMetadata() : null)
                    .filter(java.util.Objects::nonNull)
                    .toList();
            int savedCharacters = metadataList.stream()
                    .map(PromptExecutionMetadata::promptCompressionLedger)
                    .mapToInt(PromptCompressionLedger::savedCharacters)
                    .sum();
            int savedEstimatedTokens = metadataList.stream()
                    .map(PromptExecutionMetadata::promptCompressionLedger)
                    .mapToInt(PromptCompressionLedger::savedEstimatedTokens)
                    .sum();
            long compressionAppliedRounds = metadataList.stream()
                    .map(PromptExecutionMetadata::promptCompressionLedger)
                    .filter(PromptCompressionLedger::compressionApplied)
                    .count();

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("benchmarkRunId", runResult.benchmarkRunId());
            row.put("username", runResult.username());
            row.put("scenarioKey", runResult.replayRun().scenarioKey());
            row.put("scenarioFamily", runResult.replayRun().scenario().scenarioFamily());
            row.put("userProfileKey", runResult.replayRun().scenario().userProfileKey());
            row.put("roundCount", runResult.replayRun().rounds().size());
            row.put("savedCharacters", savedCharacters);
            row.put("savedEstimatedTokens", savedEstimatedTokens);
            row.put("compressionAppliedRounds", compressionAppliedRounds);
            row.put("observedBudgetProfiles", metadataList.stream()
                    .map(PromptExecutionMetadata::budgetProfile)
                    .map(profile -> profile.profileKey())
                    .distinct()
                    .toList());
            row.put("observedTransformationModes", metadataList.stream()
                    .map(PromptExecutionMetadata::promptCompressionLedger)
                    .map(PromptCompressionLedger::transformationMode)
                    .distinct()
                    .toList());
            rows.add(row);
        }
        return rows;
    }

    private List<Map<String, Object>> buildRoundRows(List<SandboxPromptBenchmarkRunResult> runResults) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (SandboxPromptBenchmarkRunResult runResult : runResults) {
            for (SandboxPromptReplayRound round : runResult.replayRun().rounds()) {
                PromptExecutionMetadata executionMetadata =
                        round.snapshot() != null ? round.snapshot().promptExecutionMetadata() : null;
                if (executionMetadata == null) {
                    continue;
                }
                PromptCompressionLedger ledger = executionMetadata.promptCompressionLedger();
                List<Map<String, Object>> operationLedger = ledger.records().stream()
                        .map(PromptCompressionRecord::toMetadataMap)
                        .toList();

                Map<String, Object> row = new LinkedHashMap<>();
                row.put("benchmarkRunId", runResult.benchmarkRunId());
                row.put("username", runResult.username());
                row.put("scenarioKey", runResult.replayRun().scenarioKey());
                row.put("scenarioFamily", runResult.replayRun().scenario().scenarioFamily());
                row.put("userProfileKey", runResult.replayRun().scenario().userProfileKey());
                row.put("roundNumber", round.roundNumber());
                row.put("roundKey", round.roundPlan().roundKey());
                row.put("requestId", round.requestId());
                row.put("requestPath", round.requestPath());
                row.put("budgetProfile", executionMetadata.budgetProfile().profileKey());
                row.put("budgetViewProfile", executionMetadata.budgetProfile().viewProfile().name());
                row.put("promptTransformationMode", ledger.transformationMode());
                row.put("rawPromptParity", ledger.rawPromptParity());
                row.put("compressionApplied", ledger.compressionApplied());
                row.put("rawSystemPromptLength", executionMetadata.rawSystemPromptLength());
                row.put("rawUserPromptLength", executionMetadata.rawUserPromptLength());
                row.put("rawTotalPromptLength", executionMetadata.rawTotalPromptLength());
                row.put("llmSystemPromptLength", executionMetadata.systemPromptLength());
                row.put("llmUserPromptLength", executionMetadata.userPromptLength());
                row.put("llmTotalPromptLength", executionMetadata.totalPromptLength());
                row.put("savedCharacters", ledger.savedCharacters());
                row.put("savedEstimatedTokens", ledger.savedEstimatedTokens());
                row.put("promptCompressionOperationCount", ledger.operationCount());
                row.put("operationScopeKeys", ledger.records().stream().map(PromptCompressionRecord::scopeKey).toList());
                row.put("operationActions", ledger.records().stream().map(record -> record.action().name()).toList());
                row.put("operationLedger", operationLedger);
                rows.add(row);
            }
        }
        return rows;
    }

    private List<Map<String, Object>> buildProfileLedger(List<Map<String, Object>> roundRows) {
        Map<String, List<Map<String, Object>>> grouped = roundRows.stream()
                .collect(Collectors.groupingBy(
                        row -> String.valueOf(row.get("budgetProfile")),
                        TreeMap::new,
                        Collectors.toList()));

        List<Map<String, Object>> rows = new ArrayList<>();
        for (Map.Entry<String, List<Map<String, Object>>> entry : grouped.entrySet()) {
            List<Map<String, Object>> rowsForProfile = entry.getValue();
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("budgetProfile", entry.getKey());
            row.put("budgetViewProfile", rowsForProfile.get(0).get("budgetViewProfile"));
            row.put("roundCount", rowsForProfile.size());
            row.put("compressionAppliedRoundCount", countTrue(rowsForProfile, "compressionApplied"));
            row.put("rawPromptParityRatePercent", percentage(countTrue(rowsForProfile, "rawPromptParity"), rowsForProfile.size()));
            row.put("averageSavedCharacters", average(rowsForProfile, "savedCharacters"));
            row.put("averageSavedEstimatedTokens", average(rowsForProfile, "savedEstimatedTokens"));
            row.put("averageRawTotalPromptLength", average(rowsForProfile, "rawTotalPromptLength"));
            row.put("averageLlmTotalPromptLength", average(rowsForProfile, "llmTotalPromptLength"));
            row.put("transformationModes", rowsForProfile.stream()
                    .map(profileRow -> String.valueOf(profileRow.get("promptTransformationMode")))
                    .distinct()
                    .sorted()
                    .toList());
            rows.add(row);
        }
        return rows;
    }

    private Map<String, Object> buildScopeOperationHistogram(List<Map<String, Object>> roundRows) {
        Map<String, Integer> histogram = new TreeMap<>();
        for (Map<String, Object> roundRow : roundRows) {
            Object operationLedger = roundRow.get("operationLedger");
            if (!(operationLedger instanceof List<?> operations)) {
                continue;
            }
            for (Object operation : operations) {
                if (!(operation instanceof Map<?, ?> operationMap)) {
                    continue;
                }
                String scopeKey = String.valueOf(operationMap.get("scopeKey"));
                String action = String.valueOf(operationMap.get("action"));
                String histogramKey = scopeKey + "::" + action;
                histogram.merge(histogramKey, 1, Integer::sum);
            }
        }
        return new LinkedHashMap<>(histogram);
    }

    private String buildMarkdown(Map<String, Object> summary, List<Map<String, Object>> profileRows) {
        StringBuilder builder = new StringBuilder();
        builder.append("# Prompt Compression Evidence\n\n");
        builder.append("- generatedAt: ").append(summary.get("generatedAt")).append('\n');
        builder.append("- runCount: ").append(summary.get("runCount")).append('\n');
        builder.append("- roundCount: ").append(summary.get("roundCount")).append('\n');
        builder.append("- averageSavedCharacters: ").append(format(summary.get("averageSavedCharacters"))).append('\n');
        builder.append("- averageSavedEstimatedTokens: ").append(format(summary.get("averageSavedEstimatedTokens"))).append('\n');
        builder.append("- compressionAppliedRatePercent: ").append(format(summary.get("compressionAppliedRatePercent"))).append('\n');
        builder.append("- rawPromptParityRatePercent: ").append(format(summary.get("rawPromptParityRatePercent"))).append("\n\n");
        builder.append("## Prompt Budget Profiles\n\n");
        for (Map<String, Object> profileRow : profileRows) {
            builder.append("- ")
                    .append(profileRow.get("budgetProfile"))
                    .append(" | view=")
                    .append(profileRow.get("budgetViewProfile"))
                    .append(" | rounds=")
                    .append(profileRow.get("roundCount"))
                    .append(" | savedChars=")
                    .append(format(profileRow.get("averageSavedCharacters")))
                    .append(" | savedTokens=")
                    .append(format(profileRow.get("averageSavedEstimatedTokens")))
                    .append('\n');
        }
        builder.append("\n## Files\n\n");
        builder.append("- compression-summary.json\n");
        builder.append("- compression-summary.md\n");
        builder.append("- compression-summary.html\n");
        builder.append("- compression-runs.ndjson\n");
        builder.append("- compression-rounds.ndjson\n");
        builder.append("- prompt-profile-ledger.ndjson\n");
        return builder.toString();
    }

    private String buildHtml(Map<String, Object> summary, List<Map<String, Object>> profileRows) {
        StringBuilder builder = new StringBuilder();
        builder.append("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">")
                .append("<title>Prompt Compression Evidence</title>")
                .append("<style>")
                .append("body{font-family:'Segoe UI',sans-serif;margin:32px;color:#1f2937;}")
                .append("table{border-collapse:collapse;width:100%;margin-top:16px;}")
                .append("th,td{border:1px solid #d1d5db;padding:8px;text-align:left;}")
                .append("th{background:#f3f4f6;}a{color:#2563eb;text-decoration:none;}")
                .append("</style></head><body>");
        builder.append("<h1>Prompt Compression Evidence</h1>");
        builder.append("<p>Generated at ").append(summary.get("generatedAt")).append("</p>");
        builder.append("<ul>");
        builder.append("<li>Run count: ").append(summary.get("runCount")).append("</li>");
        builder.append("<li>Round count: ").append(summary.get("roundCount")).append("</li>");
        builder.append("<li>Average saved characters: ").append(format(summary.get("averageSavedCharacters"))).append("</li>");
        builder.append("<li>Average saved estimated tokens: ").append(format(summary.get("averageSavedEstimatedTokens"))).append("</li>");
        builder.append("<li>Compression applied rate: ").append(format(summary.get("compressionAppliedRatePercent"))).append("%</li>");
        builder.append("<li>Raw prompt parity rate: ").append(format(summary.get("rawPromptParityRatePercent"))).append("%</li>");
        builder.append("</ul>");
        builder.append("<p><a href=\"compression-summary.json\">compression-summary.json</a> | ")
                .append("<a href=\"compression-summary.md\">compression-summary.md</a> | ")
                .append("<a href=\"compression-runs.ndjson\">compression-runs.ndjson</a> | ")
                .append("<a href=\"compression-rounds.ndjson\">compression-rounds.ndjson</a> | ")
                .append("<a href=\"prompt-profile-ledger.ndjson\">prompt-profile-ledger.ndjson</a></p>");
        builder.append("<h2>Prompt Budget Profiles</h2><table><thead><tr>")
                .append("<th>Budget Profile</th><th>View</th><th>Rounds</th><th>Applied Rounds</th>")
                .append("<th>Avg Saved Chars</th><th>Avg Saved Tokens</th><th>Parity Rate</th></tr></thead><tbody>");
        for (Map<String, Object> profileRow : profileRows) {
            builder.append("<tr><td>").append(profileRow.get("budgetProfile"))
                    .append("</td><td>").append(profileRow.get("budgetViewProfile"))
                    .append("</td><td>").append(profileRow.get("roundCount"))
                    .append("</td><td>").append(profileRow.get("compressionAppliedRoundCount"))
                    .append("</td><td>").append(format(profileRow.get("averageSavedCharacters")))
                    .append("</td><td>").append(format(profileRow.get("averageSavedEstimatedTokens")))
                    .append("</td><td>").append(format(profileRow.get("rawPromptParityRatePercent"))).append("%</td></tr>");
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

    private double average(List<Map<String, Object>> rows, String key) {
        return rows.stream()
                .map(row -> row.get(key))
                .filter(Number.class::isInstance)
                .map(Number.class::cast)
                .mapToDouble(Number::doubleValue)
                .average()
                .orElse(0.0d);
    }

    private long countTrue(List<Map<String, Object>> rows, String key) {
        return rows.stream()
                .filter(row -> Boolean.TRUE.equals(row.get(key)))
                .count();
    }

    private double percentage(long numerator, int denominator) {
        return denominator <= 0 ? 0.0d : (numerator * 100.0d) / denominator;
    }

    private String format(Object value) {
        if (value instanceof Number number) {
            return String.format(Locale.ROOT, "%.3f", number.doubleValue());
        }
        return String.valueOf(value);
    }
}
