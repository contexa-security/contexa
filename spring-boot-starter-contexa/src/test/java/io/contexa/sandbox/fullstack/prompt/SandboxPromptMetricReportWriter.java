package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 공식 지표 단위의 독립 실행 증적을 남기는 writer.
 *
 * 목적:
 * - EIR/CCR/CCSR 같은 항목별 심사 증적을 공용 summary가 아니라 개별 파일명으로 고정한다.
 * - 같은 replay run을 사용하더라도 각 지표의 성공 근거가 무엇인지 별도의 JSON/Markdown/NDJSON로 분리한다.
 */
public final class SandboxPromptMetricReportWriter {

    private final ObjectMapper objectMapper;
    private final Path reportDirectory;

    public SandboxPromptMetricReportWriter(ObjectMapper objectMapper, Path reportDirectory) {
        this.objectMapper = objectMapper;
        this.reportDirectory = reportDirectory;
    }

    public void writeMetricReport(
            String benchmarkName,
            SandboxPromptBenchmarkMetricCatalog metric,
            List<SandboxPromptBenchmarkRunResult> runResults) throws IOException {
        Files.createDirectories(reportDirectory);

        String prefix = metric.metricCode();
        String generatedAt = Instant.now().toString();
        SandboxPromptBenchmarkStatistics.Summary summary = summarize(metric, runResults);

        Map<String, Object> summaryJson = new LinkedHashMap<>();
        summaryJson.put("benchmarkName", benchmarkName);
        summaryJson.put("generatedAt", generatedAt);
        summaryJson.put("metricCode", metric.metricCode());
        summaryJson.put("metricName", metric.metricName());
        summaryJson.put("metricCategory", metric.category());
        summaryJson.put("successThreshold", metric.successThreshold());
        summaryJson.put("higherIsBetter", metric.higherIsBetter());
        summaryJson.put("runCount", runResults.size());
        summaryJson.put("scenarioKeys", runResults.stream().map(result -> result.replayRun().scenarioKey()).distinct().toList());
        summaryJson.put("scenarioFamilies", runResults.stream().map(result -> result.replayRun().scenario().scenarioFamily()).distinct().toList());
        summaryJson.put("userProfileKeys", runResults.stream().map(result -> result.replayRun().scenario().userProfileKey()).distinct().toList());
        summaryJson.put("summary", summaryRow(summary, metric));
        summaryJson.put("runLedger", buildRunLedger(metric, runResults));
        summaryJson.put("roundEvidenceLedger", buildRoundEvidenceLedger(metric, runResults));
        summaryJson.put("defectLedger", buildDefectLedger(metric, runResults));

        Files.writeString(
                reportDirectory.resolve(prefix + "-summary.json"),
                objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(summaryJson));
        Files.writeString(
                reportDirectory.resolve(prefix + "-summary.md"),
                buildMarkdown(benchmarkName, metric, summary, runResults));

        writeNdjson(reportDirectory.resolve(prefix + "-runs.ndjson"), buildRunLedger(metric, runResults));
        writeNdjson(reportDirectory.resolve(prefix + "-rounds.ndjson"), buildRoundEvidenceLedger(metric, runResults));
        writeNdjson(reportDirectory.resolve(prefix + "-defects.ndjson"), buildDefectLedger(metric, runResults));
    }

    private SandboxPromptBenchmarkStatistics.Summary summarize(
            SandboxPromptBenchmarkMetricCatalog metric,
            List<SandboxPromptBenchmarkRunResult> runResults) {
        List<Double> values = runResults.stream()
                .map(result -> result.metrics().get(metric.metricName()))
                .filter(java.util.Objects::nonNull)
                .toList();
        return SandboxPromptBenchmarkStatistics.summarize(
                values,
                metric.successThreshold(),
                metric.higherIsBetter());
    }

    private Map<String, Object> summaryRow(
            SandboxPromptBenchmarkStatistics.Summary summary,
            SandboxPromptBenchmarkMetricCatalog metric) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("sampleCount", summary.sampleCount());
        row.put("mean", summary.mean());
        row.put("median", summary.median());
        row.put("stdDev", summary.stdDev());
        row.put("min", summary.min());
        row.put("max", summary.max());
        row.put("p90", summary.p90());
        row.put("p95", summary.p95());
        row.put("p99", summary.p99());
        row.put("failureRatePercent", summary.failureRatePercent());
        row.put("ci95Low", summary.ci95Low());
        row.put("ci95High", summary.ci95High());
        row.put("stabilityClass", classifyStability(summary, metric.higherIsBetter()));
        return row;
    }

    private List<Map<String, Object>> buildRunLedger(
            SandboxPromptBenchmarkMetricCatalog metric,
            List<SandboxPromptBenchmarkRunResult> runResults) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (SandboxPromptBenchmarkRunResult result : runResults) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("benchmarkRunId", result.benchmarkRunId());
            row.put("username", result.username());
            row.put("scenarioKey", result.replayRun().scenarioKey());
            row.put("scenarioFamily", result.replayRun().scenario().scenarioFamily());
            row.put("userProfileKey", result.replayRun().scenario().userProfileKey());
            row.put("roundCount", result.replayRun().rounds().size());
            row.put("metricCode", metric.metricCode());
            row.put("metricName", metric.metricName());
            row.put("metricValue", result.metrics().get(metric.metricName()));
            row.put("successThreshold", metric.successThreshold());
            row.put("higherIsBetter", metric.higherIsBetter());
            rows.add(row);
        }
        return rows;
    }

    private List<Map<String, Object>> buildRoundEvidenceLedger(
            SandboxPromptBenchmarkMetricCatalog metric,
            List<SandboxPromptBenchmarkRunResult> runResults) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (SandboxPromptBenchmarkRunResult result : runResults) {
            for (int index = 0; index < result.replayRun().rounds().size(); index++) {
                SandboxPromptReplayRound round = result.replayRun().rounds().get(index);
                SandboxPromptTraceSnapshot snapshot = round.snapshot();
                Map<String, Object> eventMetadata = snapshot.event() != null && snapshot.event().getMetadata() != null
                        ? snapshot.event().getMetadata()
                        : Map.of();

                Map<String, Object> row = new LinkedHashMap<>();
                row.put("benchmarkRunId", result.benchmarkRunId());
                row.put("username", result.username());
                row.put("metricCode", metric.metricCode());
                row.put("metricName", metric.metricName());
                row.put("round", index + 1);
                row.put("roundKey", round.roundPlan().roundKey());
                row.put("phase", round.phase());
                row.put("behaviorPhase", round.roundPlan().behaviorPhase());
                row.put("anomalySignal", round.roundPlan().anomalySignal());
                row.put("sessionMode", round.roundPlan().sessionMode().name());
                row.put("observedAt", round.roundPlan().observedAt().toString());
                row.put("requestId", round.requestId());
                row.put("requestPath", round.requestPath());
                row.put("clientIp", round.clientIp());
                row.put("userAgentLabel", round.userAgentLabel());
                row.put("metricRoundPassRate", result.roundScorecards().get(index).passRatePercent());
                row.put("authMethodPresent", hasText(eventMetadata.get("authMethod")));
                row.put("authorizationEffectPresent", hasText(eventMetadata.get("authorizationEffect")));
                row.put("resourceSensitivityPresent", hasText(eventMetadata.get("resourceSensitivity")));
                row.put("sensitiveResourceFlag", eventMetadata.get("isSensitiveResource"));
                row.put("effectiveRolesCount", sizeOf(eventMetadata.get("effectiveRoles")));
                row.put("effectivePermissionsCount", sizeOf(eventMetadata.get("effectivePermissions")));
                row.put("sessionUserIdPresent", snapshot.sessionContext() != null && hasText(snapshot.sessionContext().getUserId()));
                row.put("sessionAuthMethodPresent", snapshot.sessionContext() != null && hasText(snapshot.sessionContext().getAuthMethod()));
                row.put("sessionRequestCount", snapshot.sessionContext() != null ? snapshot.sessionContext().getRequestCount() : null);
                row.put("behaviorCurrentOsPresent", snapshot.behaviorAnalysis() != null && hasText(snapshot.behaviorAnalysis().getCurrentUserAgentOS()));
                row.put("behaviorCurrentBrowserPresent", snapshot.behaviorAnalysis() != null && hasText(snapshot.behaviorAnalysis().getCurrentUserAgentBrowser()));
                row.put("promptExecutionMetadataPresent", snapshot.promptExecutionMetadata() != null);
                row.put("relatedDocumentsCount", snapshot.relatedDocuments() != null ? snapshot.relatedDocuments().size() : 0);
                if (metric == SandboxPromptBenchmarkMetricCatalog.CONTEXT_CONSISTENCY_RATE) {
                    String userPrompt = snapshot.userPrompt() == null ? "" : snapshot.userPrompt();
                    String requestPath = text(eventMetadata.get("requestPath"));
                    String clientIp = text(eventMetadata.get("clientIp"));
                    String resourceSensitivity = text(eventMetadata.get("resourceSensitivity"));
                    String authorizationEffect = text(eventMetadata.get("authorizationEffect"));
                    String demoPhase = text(round.responseBody().get("demoPhase"));

                    row.put("requestPathAligned", hasText(requestPath) && userPrompt.contains(requestPath));
                    row.put("clientIpAligned", hasText(clientIp) && userPrompt.contains(clientIp));
                    row.put("mfaVerifiedAligned",
                            Boolean.TRUE.equals(asBoolean(eventMetadata.get("mfaVerified"))) == userPrompt.contains("MfaVerified: true"));
                    row.put("resourceSensitivityAligned",
                            hasText(resourceSensitivity) && userPrompt.contains("Sensitivity: " + resourceSensitivity));
                    row.put("authorizationEffectAligned",
                            hasText(authorizationEffect) && userPrompt.contains("AuthorizationEffect: " + authorizationEffect));
                    row.put("demoPhaseAligned", demoPhase != null && demoPhase.equals(text(eventMetadata.get("demoPhase"))));
                } else if (metric == SandboxPromptBenchmarkMetricCatalog.PROMPT_FIDELITY_RATE) {
                    SandboxPromptFidelityAssessment fidelityAssessment = result.promptFidelityAssessments().get(index);
                    row.put("promptFidelityRate", fidelityAssessment.fidelityRate());
                    row.put("metadataSectionCount", fidelityAssessment.metadataSectionKeys().size());
                    row.put("executionSectionCount", fidelityAssessment.executionSectionKeys().size());
                    row.put("omittedSectionCount", fidelityAssessment.omittedSections().size());
                    row.put("omissionLedgerCount", fidelityAssessment.omissionLedgerCount());
                    row.put("metadataSectionKeys", fidelityAssessment.metadataSectionKeys());
                    row.put("executionSectionKeys", fidelityAssessment.executionSectionKeys());
                    row.put("omittedSections", fidelityAssessment.omittedSections());
                    row.put("systemPromptHashPresent", hasText(snapshot.metadata().get("systemPromptHash")));
                    row.put("userPromptHashPresent", hasText(snapshot.metadata().get("userPromptHash")));
                    row.put("promptHashPresent", hasText(snapshot.metadata().get("promptHash")));
                }
                rows.add(row);
            }
        }
        return rows;
    }

    private List<Map<String, Object>> buildDefectLedger(
            SandboxPromptBenchmarkMetricCatalog metric,
            List<SandboxPromptBenchmarkRunResult> runResults) {
        return runResults.stream()
                .flatMap(result -> result.defectFindings().stream()
                        .filter(finding -> isRelevantToMetric(metric, finding))
                        .map(finding -> {
                            Map<String, Object> row = new LinkedHashMap<>();
                            row.put("benchmarkRunId", finding.benchmarkRunId());
                            row.put("username", finding.username());
                            row.put("source", finding.source());
                            row.put("code", finding.code());
                            row.put("category", finding.category().name());
                            row.put("summary", finding.summary());
                            row.put("detail", finding.detail());
                            return row;
                        }))
                .toList();
    }

    private String buildMarkdown(
            String benchmarkName,
            SandboxPromptBenchmarkMetricCatalog metric,
            SandboxPromptBenchmarkStatistics.Summary summary,
            List<SandboxPromptBenchmarkRunResult> runResults) {
        StringBuilder builder = new StringBuilder();
        builder.append("# ").append(benchmarkName).append(" - ").append(metric.metricCode()).append("\n\n");
        builder.append("- metricName: ").append(metric.metricName()).append('\n');
        builder.append("- category: ").append(metric.category()).append('\n');
        builder.append("- successThreshold: ").append(metric.successThreshold()).append('\n');
        builder.append("- higherIsBetter: ").append(metric.higherIsBetter()).append("\n\n");
        builder.append("## Summary\n\n");
        builder.append("- sampleCount: ").append(summary.sampleCount()).append('\n');
        builder.append("- mean: ").append(String.format(Locale.ROOT, "%.6f", summary.mean())).append('\n');
        builder.append("- failureRatePercent: ").append(String.format(Locale.ROOT, "%.6f", summary.failureRatePercent())).append('\n');
        builder.append("- min: ").append(String.format(Locale.ROOT, "%.6f", summary.min())).append('\n');
        builder.append("- max: ").append(String.format(Locale.ROOT, "%.6f", summary.max())).append('\n');
        builder.append("- ci95Low: ").append(String.format(Locale.ROOT, "%.6f", summary.ci95Low())).append('\n');
        builder.append("- ci95High: ").append(String.format(Locale.ROOT, "%.6f", summary.ci95High())).append('\n');
        builder.append("- stabilityClass: ").append(classifyStability(summary, metric.higherIsBetter())).append("\n\n");
        builder.append("## Run Ledger\n\n");
        for (Map<String, Object> row : buildRunLedger(metric, runResults)) {
            builder.append("- ").append(row.get("benchmarkRunId"))
                    .append(" | metricValue=").append(row.get("metricValue"))
                    .append(" | scenarioKey=").append(row.get("scenarioKey"))
                    .append(" | roundCount=").append(row.get("roundCount"))
                    .append('\n');
        }
        builder.append('\n');
        builder.append("## Files\n\n");
        builder.append("- ").append(metric.metricCode()).append("-summary.json\n");
        builder.append("- ").append(metric.metricCode()).append("-summary.md\n");
        builder.append("- ").append(metric.metricCode()).append("-runs.ndjson\n");
        builder.append("- ").append(metric.metricCode()).append("-rounds.ndjson\n");
        builder.append("- ").append(metric.metricCode()).append("-defects.ndjson\n");
        return builder.toString();
    }

    private void writeNdjson(Path outputPath, List<Map<String, Object>> rows) throws IOException {
        StringBuilder builder = new StringBuilder();
        for (Map<String, Object> row : rows) {
            builder.append(objectMapper.writeValueAsString(row)).append('\n');
        }
        Files.writeString(outputPath, builder.toString());
    }

    private static boolean hasText(Object value) {
        return value != null && !String.valueOf(value).isBlank();
    }

    private static int sizeOf(Object value) {
        return value instanceof List<?> list ? list.size() : 0;
    }

    private static String text(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static Boolean asBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String text) {
            return Boolean.parseBoolean(text);
        }
        return null;
    }

    private static boolean isRelevantToMetric(
            SandboxPromptBenchmarkMetricCatalog metric,
            SandboxPromptDefectFinding finding) {
        if (metric == null || finding == null) {
            return false;
        }
        String code = text(finding.code());
        String summary = text(finding.summary());
        String detail = text(finding.detail());
        String corpus = ((code == null ? "" : code) + " "
                + (summary == null ? "" : summary) + " "
                + (detail == null ? "" : detail)).toUpperCase(Locale.ROOT);

        return switch (metric) {
            case EVENT_INTEGRITY_RATE -> containsAny(corpus,
                    "TRACE_EVENT",
                    "TRACE_REQUEST_ID",
                    "AUTHMETHOD",
                    "AUTHORIZATIONEFFECT",
                    "EFFECTIVEROLES",
                    "EFFECTIVEPERMISSIONS",
                    "CLIENTIP",
                    "REQUESTPATH");
            case CONTEXT_COMPLETENESS_RATE -> containsAny(corpus,
                    "AUTHMETHOD",
                    "AUTHORIZATIONEFFECT",
                    "RESOURCESENSITIVITY",
                    "SENSITIVERESOURCE",
                    "EFFECTIVEROLES",
                    "EFFECTIVEPERMISSIONS",
                    "SESSIONUSERID",
                    "SESSIONAUTHMETHOD",
                    "SESSIONREQUESTCOUNT",
                    "BEHAVIORCURRENTOS",
                    "BEHAVIORCURRENTBROWSER",
                    "PROMPTEXECUTIONMETADATA");
            case CONTEXT_CONSISTENCY_RATE -> containsAny(corpus,
                    "MISMATCH",
                    "MATCH",
                    "REQUESTPATH",
                    "CLIENTIP",
                    "MFAVERIFIED",
                    "SENSITIVITY",
                    "AUTHORIZATIONEFFECT",
                    "DEMOPHASE");
            case PROMPT_FIDELITY_RATE -> containsAny(corpus,
                    "PROMPT_",
                    "SECTION_SET",
                    "OMITTED_SECTIONS",
                    "OMISSION_LEDGER",
                    "SYSTEM_PROMPT_HASH",
                    "USER_PROMPT_HASH",
                    "PROMPT_HASH",
                    "PROMPT_LENGTH",
                    "RENDERED_MATCH");
            default -> true;
        };
    }

    private static boolean containsAny(String corpus, String... tokens) {
        if (corpus == null || corpus.isBlank() || tokens == null) {
            return false;
        }
        for (String token : tokens) {
            if (token != null && !token.isBlank() && corpus.contains(token)) {
                return true;
            }
        }
        return false;
    }

    private static String classifyStability(SandboxPromptBenchmarkStatistics.Summary summary, boolean higherIsBetter) {
        if (summary == null || summary.sampleCount() <= 1) {
            return "STABLE";
        }
        if (summary.failureRatePercent() > 0.0d) {
            return "FLAKY";
        }
        double meanAbs = Math.abs(summary.mean());
        double coefficientOfVariationPercent = meanAbs < 0.000001d ? 0.0d : (summary.stdDev() / meanAbs) * 100.0d;
        if (coefficientOfVariationPercent >= 5.0d || summary.stdDev() >= 3.0d) {
            return "VARIABLE";
        }
        if (!higherIsBetter && summary.max() > 0.0d) {
            return "VARIABLE";
        }
        return "STABLE";
    }
}
