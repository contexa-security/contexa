package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * sandbox benchmark 결과를 JSON/Markdown/NDJSON로 정리한다.
 *
 * 목표:
 * - 반복 실행 분산과 실패 패턴을 공식 지표 형태로 남긴다.
 * - run/round/metric/defect/history 단위로 warehouse 스타일 출력을 만든다.
 * - promptVersion / contractVersion / benchmarkVersion drift를 추적한다.
 */
public class SandboxPromptBenchmarkReportWriter {

    private static final String BENCHMARK_VERSION = "SANDBOX_FULLSTACK_PROMPT_BENCHMARK_V2";

    private final ObjectMapper objectMapper;
    private final Path reportDirectory;

    public SandboxPromptBenchmarkReportWriter(ObjectMapper objectMapper, Path reportDirectory) {
        this.objectMapper = objectMapper;
        this.reportDirectory = reportDirectory;
    }

    public void writeReport(String benchmarkName, List<SandboxPromptBenchmarkRunResult> runResults) throws IOException {
        Files.createDirectories(reportDirectory);
        Map<String, Object> previousHistory = readPreviousHistoryRow();
        cleanCurrentReportFiles();

        String generatedAt = Instant.now().toString();
        Map<String, Object> metricSummary = buildMetricSummary(runResults);
        Map<String, Object> jsonReport = new LinkedHashMap<>();
        jsonReport.put("benchmarkName", benchmarkName);
        jsonReport.put("benchmarkVersion", BENCHMARK_VERSION);
        jsonReport.put("generatedAt", generatedAt);
        jsonReport.put("runCount", runResults.size());
        jsonReport.put("metricCatalog", buildMetricCatalog());
        jsonReport.put("officialMetricCoverage", buildOfficialMetricCoverage(metricSummary));
        jsonReport.put("observedPromptVersions", collectObservedPromptVersions(runResults));
        jsonReport.put("observedContractVersions", collectObservedContractVersions(runResults));
        jsonReport.put("observedTemplateKeys", collectObservedTemplateKeys(runResults));
        jsonReport.put("observedUserProfileKeys", collectObservedUserProfileKeys(runResults));
        jsonReport.put("observedScenarioFamilies", collectObservedScenarioFamilies(runResults));
        jsonReport.put("metricSummaries", metricSummary);
        jsonReport.put("metricDriftFromPreviousRun", buildMetricDrift(previousHistory, metricSummary));
        jsonReport.put("flakinessDashboard", buildFlakinessDashboard(metricSummary));
        jsonReport.put("defectCategorySummary", buildDefectCategorySummary(runResults));
        jsonReport.put("responsibilityBoundarySummary", buildResponsibilityBoundarySummary(runResults));
        jsonReport.put("scenarioSummaries", buildScenarioSummaries(runResults));
        jsonReport.put("experimentGroupSummaries", buildExperimentGroupSummaries(runResults));
        jsonReport.put("userProfileSummaries", buildUserProfileSummaries(runResults));
        jsonReport.put("scenarioFamilySummaries", buildScenarioFamilySummaries(runResults));
        jsonReport.put("runLedger", buildRunLedger(runResults));
        jsonReport.put("roundLedger", buildRoundLedger(runResults));
        jsonReport.put("promptFidelityLedger", buildPromptFidelityLedger(runResults));
        jsonReport.put("defectLedger", buildDefectLedger(runResults));

        Files.writeString(
                reportDirectory.resolve("summary.json"),
                objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonReport));
        Files.writeString(
                reportDirectory.resolve("summary.md"),
                buildMarkdown(benchmarkName, runResults, jsonReport));
        Files.writeString(
                reportDirectory.resolve("summary.html"),
                buildHtml(benchmarkName, jsonReport));

        writeNdjson(reportDirectory.resolve("runs.ndjson"), buildRunLedger(runResults));
        writeNdjson(reportDirectory.resolve("rounds.ndjson"), buildRoundLedger(runResults));
        writeNdjson(reportDirectory.resolve("metrics.ndjson"), buildMetricLedger(runResults));
        writeNdjson(reportDirectory.resolve("prompt-fidelity.ndjson"), buildPromptFidelityLedger(runResults));
        writeNdjson(reportDirectory.resolve("defects.ndjson"), buildDefectLedger(runResults));
        writeNdjson(reportDirectory.resolve("scenarios.ndjson"), buildScenarioSummaries(runResults));
        writeNdjson(reportDirectory.resolve("experiment-groups.ndjson"), buildExperimentGroupSummaries(runResults));
        writeNdjson(reportDirectory.resolve("user-profiles.ndjson"), buildUserProfileSummaries(runResults));
        writeNdjson(reportDirectory.resolve("scenario-families.ndjson"), buildScenarioFamilySummaries(runResults));
        writeNdjson(reportDirectory.resolve("metric-catalog.ndjson"), buildMetricCatalog());

        Map<String, Object> historyRow = buildHistoryRow(benchmarkName, generatedAt, runResults);
        Files.writeString(
                reportDirectory.resolve("latest-history.json"),
                objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(historyRow));
        appendNdjson(reportDirectory.resolve("history.ndjson"), historyRow);

        new SandboxPromptCompressionEvidenceWriter(objectMapper, reportDirectory.resolve("compression"))
                .write(runResults);
    }

    private Map<String, Object> buildMetricSummary(List<SandboxPromptBenchmarkRunResult> runResults) {
        Map<String, Object> summaries = new LinkedHashMap<>();
        TreeSet<String> metricNames = runResults.stream()
                .flatMap(result -> result.metrics().keySet().stream())
                .collect(Collectors.toCollection(TreeSet::new));

        for (String metricName : metricNames) {
            List<Double> values = runResults.stream()
                    .map(result -> result.metrics().get(metricName))
                    .filter(value -> value != null)
                    .toList();
            SandboxPromptBenchmarkMetricPolicy.MetricRule metricRule =
                    SandboxPromptBenchmarkMetricPolicy.ruleFor(metricName);

            SandboxPromptBenchmarkStatistics.Summary summary =
                    SandboxPromptBenchmarkStatistics.summarize(
                            values,
                            metricRule.successThreshold(),
                            metricRule.higherIsBetter());

            Map<String, Object> serialized = new LinkedHashMap<>();
            SandboxPromptBenchmarkMetricCatalog.findByMetricName(metricName)
                    .ifPresent(metric -> {
                        serialized.put("metricCode", metric.metricCode());
                        serialized.put("category", metric.category());
                        serialized.put("official", metric.official());
                        serialized.put("implemented", metric.implemented());
                    });
            serialized.put("successThreshold", metricRule.successThreshold());
            serialized.put("higherIsBetter", metricRule.higherIsBetter());
            serialized.put("sampleCount", summary.sampleCount());
            serialized.put("mean", summary.mean());
            serialized.put("median", summary.median());
            serialized.put("stdDev", summary.stdDev());
            serialized.put("p90", summary.p90());
            serialized.put("p95", summary.p95());
            serialized.put("p99", summary.p99());
            serialized.put("min", summary.min());
            serialized.put("max", summary.max());
            serialized.put("failureRatePercent", summary.failureRatePercent());
            serialized.put("ci95Low", summary.ci95Low());
            serialized.put("ci95High", summary.ci95High());
            serialized.put("stabilityClass", classifyStability(summary, metricRule.higherIsBetter()));
            serialized.put("coefficientOfVariationPercent", coefficientOfVariationPercent(summary));
            summaries.put(metricName, serialized);
        }
        return summaries;
    }

    private Map<String, Object> buildFlakinessDashboard(Map<String, Object> metricSummary) {
        Map<String, Object> dashboard = new LinkedHashMap<>();
        int flakyMetricCount = 0;
        int variableMetricCount = 0;

        for (Map.Entry<String, Object> entry : metricSummary.entrySet()) {
            @SuppressWarnings("unchecked")
            Map<String, Object> summary = (Map<String, Object>) entry.getValue();
            String stabilityClass = String.valueOf(summary.get("stabilityClass"));
            if ("FLAKY".equals(stabilityClass)) {
                flakyMetricCount++;
            } else if ("VARIABLE".equals(stabilityClass)) {
                variableMetricCount++;
            }
        }

        dashboard.put("flakyMetricCount", flakyMetricCount);
        dashboard.put("variableMetricCount", variableMetricCount);
        dashboard.put("stableMetricCount", metricSummary.size() - flakyMetricCount - variableMetricCount);
        dashboard.put("metrics", metricSummary);
        return dashboard;
    }

    private List<Map<String, Object>> buildScenarioSummaries(List<SandboxPromptBenchmarkRunResult> runResults) {
        return buildGroupedSummaries(runResults, result -> result.replayRun().scenarioKey(), "scenarioKey");
    }

    private List<Map<String, Object>> buildExperimentGroupSummaries(List<SandboxPromptBenchmarkRunResult> runResults) {
        return buildGroupedSummaries(runResults, result -> result.replayRun().experimentGroup(), "experimentGroup");
    }

    private List<Map<String, Object>> buildUserProfileSummaries(List<SandboxPromptBenchmarkRunResult> runResults) {
        return buildGroupedSummaries(runResults, result -> result.replayRun().scenario().userProfileKey(), "userProfileKey");
    }

    private List<Map<String, Object>> buildScenarioFamilySummaries(List<SandboxPromptBenchmarkRunResult> runResults) {
        return buildGroupedSummaries(runResults, result -> result.replayRun().scenario().scenarioFamily(), "scenarioFamily");
    }

    private List<Map<String, Object>> buildMetricCatalog() {
        return java.util.Arrays.stream(SandboxPromptBenchmarkMetricCatalog.values())
                .map(SandboxPromptBenchmarkMetricCatalog::toMap)
                .toList();
    }

    private Map<String, Object> buildOfficialMetricCoverage(Map<String, Object> metricSummary) {
        TreeSet<String> observedImplementedMetricNames = new TreeSet<>(metricSummary.keySet());
        observedImplementedMetricNames.addAll(loadExternalDecisionMetricNames());

        List<String> implementedOfficialMetrics = SandboxPromptBenchmarkMetricCatalog.implementedOfficialMetrics().stream()
                .filter(metric -> observedImplementedMetricNames.contains(metric.metricName()))
                .map(SandboxPromptBenchmarkMetricCatalog::metricName)
                .toList();
        List<String> pendingOfficialMetrics = SandboxPromptBenchmarkMetricCatalog.pendingOfficialMetrics().stream()
                .map(SandboxPromptBenchmarkMetricCatalog::metricName)
                .toList();
        List<String> missingImplementedOfficialMetrics = SandboxPromptBenchmarkMetricCatalog.implementedOfficialMetrics().stream()
                .map(SandboxPromptBenchmarkMetricCatalog::metricName)
                .filter(metricName -> !observedImplementedMetricNames.contains(metricName))
                .toList();

        Map<String, Object> coverage = new LinkedHashMap<>();
        coverage.put("officialMetricTargetCount", SandboxPromptBenchmarkMetricCatalog.officialMetrics().size());
        coverage.put("implementedOfficialMetricCount", implementedOfficialMetrics.size());
        coverage.put("pendingOfficialMetricCount", pendingOfficialMetrics.size());
        coverage.put("implementedOfficialMetrics", implementedOfficialMetrics);
        coverage.put("missingImplementedOfficialMetrics", missingImplementedOfficialMetrics);
        coverage.put("pendingOfficialMetrics", pendingOfficialMetrics);
        coverage.put("externalDecisionSummaryAvailable", Files.exists(reportDirectory.resolve("decision-summary.json")));
        coverage.put("externalDecisionMetricNames", loadExternalDecisionMetricNames());
        return coverage;
    }

    private List<String> loadExternalDecisionMetricNames() {
        Path decisionSummaryPath = reportDirectory.resolve("decision-summary.json");
        if (!Files.exists(decisionSummaryPath)) {
            return List.of();
        }
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> summary = objectMapper.readValue(Files.readString(decisionSummaryPath), Map.class);
            Object metrics = summary.get("metrics");
            if (!(metrics instanceof Map<?, ?> metricMap)) {
                return List.of();
            }
            return metricMap.keySet().stream()
                    .map(String::valueOf)
                    .sorted()
                    .toList();
        } catch (IOException ignored) {
            return List.of();
        }
    }

    private List<Map<String, Object>> buildGroupedSummaries(
            List<SandboxPromptBenchmarkRunResult> runResults,
            Function<SandboxPromptBenchmarkRunResult, String> groupKeyExtractor,
            String groupLabel) {
        return runResults.stream()
                .collect(Collectors.groupingBy(groupKeyExtractor, LinkedHashMap::new, Collectors.toList()))
                .entrySet().stream()
                .map(entry -> {
                    List<SandboxPromptBenchmarkRunResult> groupRuns = entry.getValue();
                    Map<String, Object> summary = new LinkedHashMap<>();
                    summary.put(groupLabel, entry.getKey());
                    summary.put("runCount", groupRuns.size());
                    summary.put("roundCountSet", groupRuns.stream()
                            .map(result -> result.replayRun().rounds().size())
                            .distinct()
                            .sorted()
                            .toList());
                    summary.put("scenarioFamilies", groupRuns.stream()
                            .map(result -> result.replayRun().scenario().scenarioFamily())
                            .distinct()
                            .sorted()
                            .toList());
                    summary.put("userProfileKeys", groupRuns.stream()
                            .map(result -> result.replayRun().scenario().userProfileKey())
                            .distinct()
                            .sorted()
                            .toList());
                    summary.put("metricSummaries", buildMetricSummary(groupRuns));
                    summary.put("defectCategorySummary", buildDefectCategorySummary(groupRuns));
                    summary.put("observedPromptVersions", collectObservedPromptVersions(groupRuns));
                    summary.put("observedContractVersions", collectObservedContractVersions(groupRuns));
                    summary.put("observedTemplateKeys", collectObservedTemplateKeys(groupRuns));
                    return summary;
                })
                .toList();
    }

    private Map<String, Object> buildResponsibilityBoundarySummary(List<SandboxPromptBenchmarkRunResult> runResults) {
        long implementationDefectCount = countDefects(runResults, SandboxPromptDefectCategory.IMPLEMENTATION_DEFECT);
        long dataQualityDefectCount = countDefects(runResults, SandboxPromptDefectCategory.DATA_QUALITY_DEFECT);
        long observabilityDefectCount = countDefects(runResults, SandboxPromptDefectCategory.OBSERVABILITY_DEFECT);
        long llmEvaluableGapCount = countDefects(runResults, SandboxPromptDefectCategory.LLM_EVALUABLE_GAP);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("deterministicGateDefectCount",
                implementationDefectCount + dataQualityDefectCount + observabilityDefectCount);
        summary.put("implementationDefectCount", implementationDefectCount);
        summary.put("dataQualityDefectCount", dataQualityDefectCount);
        summary.put("observabilityDefectCount", observabilityDefectCount);
        summary.put("llmEvaluableGapCount", llmEvaluableGapCount);
        summary.put("llmEvaluableZoneEnabled",
                implementationDefectCount == 0L && dataQualityDefectCount == 0L && observabilityDefectCount == 0L);
        return summary;
    }

    private long countDefects(List<SandboxPromptBenchmarkRunResult> runResults, SandboxPromptDefectCategory category) {
        return runResults.stream()
                .flatMap(result -> result.defectFindings().stream())
                .filter(finding -> finding.category() == category)
                .count();
    }

    private Map<String, Object> buildMetricDrift(
            Map<String, Object> previousHistory,
            Map<String, Object> currentMetricSummary) {
        if (previousHistory.isEmpty()) {
            return Map.of(
                    "previousRunAvailable", false,
                    "metricDeltaCount", 0,
                    "metrics", Map.of());
        }

        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> previousMetricSummary =
                (Map<String, Map<String, Object>>) previousHistory.get("metricSummaries");

        if (previousMetricSummary == null || previousMetricSummary.isEmpty()) {
            return Map.of(
                    "previousRunAvailable", false,
                    "metricDeltaCount", 0,
                    "metrics", Map.of());
        }

        Map<String, Object> driftMetrics = new LinkedHashMap<>();
        int improvedCount = 0;
        int regressedCount = 0;

        for (Map.Entry<String, Object> entry : currentMetricSummary.entrySet()) {
            if (!(entry.getValue() instanceof Map<?, ?> currentValueMap)) {
                continue;
            }

            Map<String, Object> currentMetric = new LinkedHashMap<>();
            currentValueMap.forEach((key, value) -> currentMetric.put(String.valueOf(key), value));

            Map<String, Object> previous = previousMetricSummary.get(entry.getKey());
            if (previous == null) {
                continue;
            }

            double previousMean = asDouble(previous.get("mean"));
            double currentMean = asDouble(currentMetric.get("mean"));
            double delta = currentMean - previousMean;
            boolean higherIsBetter = Boolean.TRUE.equals(currentMetric.get("higherIsBetter"));
            double normalizedDelta = higherIsBetter ? delta : -delta;

            if (normalizedDelta > 0.000001d) {
                improvedCount++;
            } else if (normalizedDelta < -0.000001d) {
                regressedCount++;
            }

            Map<String, Object> metricDelta = new LinkedHashMap<>();
            metricDelta.put("previousMean", previousMean);
            metricDelta.put("currentMean", currentMean);
            metricDelta.put("delta", delta);
            metricDelta.put("higherIsBetter", higherIsBetter);
            driftMetrics.put(entry.getKey(), metricDelta);
        }

        Map<String, Object> drift = new LinkedHashMap<>();
        drift.put("previousRunAvailable", true);
        drift.put("previousGeneratedAt", previousHistory.get("generatedAt"));
        drift.put("metricDeltaCount", driftMetrics.size());
        drift.put("improvedMetricCount", improvedCount);
        drift.put("regressedMetricCount", regressedCount);
        drift.put("metrics", driftMetrics);
        return drift;
    }

    private List<Map<String, Object>> buildRunLedger(List<SandboxPromptBenchmarkRunResult> runResults) {
        return runResults.stream()
                .map(result -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("benchmarkRunId", result.benchmarkRunId());
                    row.put("username", result.username());
                    row.put("scenarioKey", result.replayRun().scenarioKey());
                    row.put("experimentGroup", result.replayRun().experimentGroup());
                    row.put("userProfileKey", result.replayRun().scenario().userProfileKey());
                    row.put("scenarioFamily", result.replayRun().scenario().scenarioFamily());
                    row.put("roundCount", result.replayRun().rounds().size());
                    row.put("roundRequestIds", result.replayRun().rounds().stream()
                            .map(SandboxPromptReplayRound::requestId)
                            .toList());
                    row.put("roundRequestPaths", result.replayRun().rounds().stream()
                            .map(SandboxPromptReplayRound::requestPath)
                            .toList());
                    row.put("firstRoundRequestId", result.replayRun().firstRound().requestId());
                    row.put("secondRoundRequestId", result.replayRun().secondRound().requestId());
                    row.put("thirdRoundRequestId", result.replayRun().thirdRound().requestId());
                    row.put("roundPassRates", result.roundScorecards().stream()
                            .map(SandboxPromptQualityScorecard::passRatePercent)
                            .toList());
                    row.put("traceContractPassRates", result.traceContractAssessments().stream()
                            .map(SandboxPromptTraceContractAssessment::complianceRate)
                            .toList());
                    row.put("promptFidelityRates", result.promptFidelityAssessments().stream()
                            .map(SandboxPromptFidelityAssessment::fidelityRate)
                            .toList());
                    row.put("artifactIntegrityRates", result.artifactIntegrityAssessments().stream()
                            .map(SandboxPromptArtifactIntegrityAssessment::integrityRate)
                            .toList());
                    row.put("progressionPassRate", result.progressionScorecard().passRatePercent());
                    row.put("defectCount", result.defectFindings().size());
                    row.put("metrics", result.metrics());
                    return row;
                })
                .toList();
    }

    private Map<String, Object> buildDefectCategorySummary(List<SandboxPromptBenchmarkRunResult> runResults) {
        Map<String, Long> counts = runResults.stream()
                .flatMap(result -> result.defectFindings().stream())
                .collect(Collectors.groupingBy(
                        finding -> finding.category().name(),
                        LinkedHashMap::new,
                        Collectors.counting()));

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalDefectCount", runResults.stream().mapToLong(result -> result.defectFindings().size()).sum());
        summary.put("categoryCounts", counts);
        return summary;
    }

    private List<Map<String, Object>> buildDefectLedger(List<SandboxPromptBenchmarkRunResult> runResults) {
        return runResults.stream()
                .flatMap(result -> result.defectFindings().stream())
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
                })
                .toList();
    }

    private List<Map<String, Object>> buildPromptFidelityLedger(List<SandboxPromptBenchmarkRunResult> runResults) {
        return runResults.stream()
                .flatMap(result -> java.util.stream.IntStream.range(0, result.promptFidelityAssessments().size())
                        .mapToObj(index -> {
                            SandboxPromptFidelityAssessment assessment = result.promptFidelityAssessments().get(index);
                            Map<String, Object> row = new LinkedHashMap<>();
                            row.put("benchmarkRunId", result.benchmarkRunId());
                            row.put("username", result.username());
                            row.put("scenarioKey", result.replayRun().scenarioKey());
                            row.put("experimentGroup", result.replayRun().experimentGroup());
                            row.put("round", index + 1);
                            row.put("source", assessment.source());
                            row.put("fidelityRate", assessment.fidelityRate());
                            row.put("metadataSectionKeys", assessment.metadataSectionKeys());
                            row.put("executionSectionKeys", assessment.executionSectionKeys());
                            row.put("omittedSections", assessment.omittedSections());
                            row.put("omissionLedgerCount", assessment.omissionLedgerCount());
                            row.put("findingCount", assessment.findings().size());
                            return row;
                        }))
                .toList();
    }

    private List<Map<String, Object>> buildRoundLedger(List<SandboxPromptBenchmarkRunResult> runResults) {
        return runResults.stream()
                .flatMap(result -> {
                    List<SandboxPromptReplayRound> rounds = result.replayRun().rounds();
                    return java.util.stream.IntStream.range(0, rounds.size())
                            .mapToObj(index -> roundRow(result, index + 1, rounds.get(index)));
                })
                .toList();
    }

    private Map<String, Object> roundRow(
            SandboxPromptBenchmarkRunResult result,
            int roundNumber,
            SandboxPromptReplayRound round) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("benchmarkRunId", result.benchmarkRunId());
        row.put("username", result.username());
        row.put("scenarioKey", result.replayRun().scenarioKey());
        row.put("experimentGroup", result.replayRun().experimentGroup());
        row.put("userProfileKey", result.replayRun().scenario().userProfileKey());
        row.put("scenarioFamily", result.replayRun().scenario().scenarioFamily());
        row.put("round", roundNumber);
        row.put("roundKey", round.roundPlan().roundKey());
        row.put("phase", round.phase());
        row.put("behaviorPhase", round.roundPlan().behaviorPhase());
        row.put("anomalySignal", round.roundPlan().anomalySignal());
        row.put("sessionMode", round.roundPlan().sessionMode().name());
        row.put("observedAt", round.roundPlan().observedAt().toString());
        row.put("deviceAlias", round.roundPlan().deviceAlias());
        row.put("expectationNote", round.roundPlan().expectationNote());
        row.put("semanticMarkers", round.roundPlan().semanticMarkers());
        row.put("requestId", round.requestId());
        row.put("requestPath", round.requestPath());
        row.put("clientIp", round.clientIp());
        row.put("userAgentLabel", round.userAgentLabel());
        row.put("passRatePercent", result.roundScorecards().get(roundNumber - 1).passRatePercent());
        row.put("traceContractCompliance", result.traceContractAssessments().get(roundNumber - 1).complianceRate());
        row.put("promptFidelityRate", result.promptFidelityAssessments().get(roundNumber - 1).fidelityRate());
        row.put("artifactIntegrity", result.artifactIntegrityAssessments().get(roundNumber - 1).integrityRate());
        row.put("relatedDocumentsCount", safeSize(round.snapshot().relatedDocuments()));
        row.put("rawRetrievedCount", round.snapshot().retrievalAudit() != null ? round.snapshot().retrievalAudit().rawRetrievedCount() : 0);
        row.put("authorizeAllowedCount", round.snapshot().retrievalAudit() != null ? round.snapshot().retrievalAudit().authorizeAllowedCount() : 0);
        row.put("authorizeDeniedCount", round.snapshot().retrievalAudit() != null ? round.snapshot().retrievalAudit().authorizeDeniedCount() : 0);
        Map<String, Object> eventMetadata = round.snapshot().event() != null && round.snapshot().event().getMetadata() != null
                ? round.snapshot().event().getMetadata()
                : Map.of();
        row.put("eventRecentRequestCount", eventMetadata.get("recentRequestCount"));
        row.put("eventIsNewSession", eventMetadata.get("isNewSession"));
        row.put("eventIsNewDevice", eventMetadata.get("isNewDevice"));
        row.put("eventIsNewUser", eventMetadata.get("isNewUser"));
        row.put("sessionRequestCount", round.snapshot().sessionContext() != null ? round.snapshot().sessionContext().getRequestCount() : null);
        row.put("behaviorPreviousPathPresent", round.snapshot().behaviorAnalysis() != null
                && round.snapshot().behaviorAnalysis().getPreviousPath() != null);
        row.put("promptVersion", round.snapshot().metadata().get("promptVersion"));
        row.put("contractVersion", round.snapshot().metadata().get("contractVersion"));
        row.put("templateKey", round.snapshot().metadata().get("templateKey"));
        row.put("promptSectionSet", round.snapshot().metadata().get("promptSectionSet"));
        row.put("omittedSections", round.snapshot().metadata().get("omittedSections"));
        return row;
    }

    private List<Map<String, Object>> buildMetricLedger(List<SandboxPromptBenchmarkRunResult> runResults) {
        return runResults.stream()
                .flatMap(result -> result.metrics().entrySet().stream()
                        .map(entry -> {
                            Map<String, Object> row = new LinkedHashMap<>();
                            row.put("benchmarkRunId", result.benchmarkRunId());
                            row.put("username", result.username());
                            row.put("scenarioKey", result.replayRun().scenarioKey());
                            row.put("experimentGroup", result.replayRun().experimentGroup());
                            row.put("userProfileKey", result.replayRun().scenario().userProfileKey());
                            row.put("scenarioFamily", result.replayRun().scenario().scenarioFamily());
                            row.put("metricName", entry.getKey());
                            row.put("metricValue", entry.getValue());
                            SandboxPromptBenchmarkMetricCatalog.findByMetricName(entry.getKey()).ifPresent(metric -> {
                                row.put("metricCode", metric.metricCode());
                                row.put("metricCategory", metric.category());
                                row.put("officialMetric", metric.official());
                                row.put("implementedMetric", metric.implemented());
                            });
                            return row;
                        }))
                .toList();
    }

    private List<String> collectObservedPromptVersions(List<SandboxPromptBenchmarkRunResult> runResults) {
        return runResults.stream()
                .flatMap(result -> result.replayRun().rounds().stream()
                        .map(round -> String.valueOf(round.snapshot().metadata().get("promptVersion"))))
                .filter(value -> value != null && !"null".equals(value))
                .distinct()
                .toList();
    }

    private List<String> collectObservedContractVersions(List<SandboxPromptBenchmarkRunResult> runResults) {
        return runResults.stream()
                .flatMap(result -> result.replayRun().rounds().stream()
                        .map(round -> String.valueOf(round.snapshot().metadata().get("contractVersion"))))
                .filter(value -> value != null && !"null".equals(value))
                .distinct()
                .toList();
    }

    private List<String> collectObservedTemplateKeys(List<SandboxPromptBenchmarkRunResult> runResults) {
        return runResults.stream()
                .flatMap(result -> result.replayRun().rounds().stream()
                        .map(round -> String.valueOf(round.snapshot().metadata().get("templateKey"))))
                .filter(value -> value != null && !"null".equals(value))
                .distinct()
                .toList();
    }

    private List<String> collectObservedUserProfileKeys(List<SandboxPromptBenchmarkRunResult> runResults) {
        return runResults.stream()
                .map(result -> result.replayRun().scenario().userProfileKey())
                .filter(value -> value != null && !"null".equals(value))
                .distinct()
                .toList();
    }

    private List<String> collectObservedScenarioFamilies(List<SandboxPromptBenchmarkRunResult> runResults) {
        return runResults.stream()
                .map(result -> result.replayRun().scenario().scenarioFamily())
                .filter(value -> value != null && !"null".equals(value))
                .distinct()
                .toList();
    }

    private Map<String, Object> buildHistoryRow(
            String benchmarkName,
            String generatedAt,
            List<SandboxPromptBenchmarkRunResult> runResults) {
        Map<String, Object> metricSummary = buildMetricSummary(runResults);
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("benchmarkName", benchmarkName);
        row.put("benchmarkVersion", BENCHMARK_VERSION);
        row.put("generatedAt", generatedAt);
        row.put("runCount", runResults.size());
        row.put("scenarioKeys", runResults.stream().map(result -> result.replayRun().scenarioKey()).distinct().toList());
        row.put("experimentGroups", runResults.stream().map(result -> result.replayRun().experimentGroup()).distinct().toList());
        row.put("userProfileKeys", collectObservedUserProfileKeys(runResults));
        row.put("scenarioFamilies", collectObservedScenarioFamilies(runResults));
        row.put("metricCatalog", buildMetricCatalog());
        row.put("officialMetricCoverage", buildOfficialMetricCoverage(metricSummary));
        row.put("observedPromptVersions", collectObservedPromptVersions(runResults));
        row.put("observedContractVersions", collectObservedContractVersions(runResults));
        row.put("observedTemplateKeys", collectObservedTemplateKeys(runResults));
        row.put("metricSummaries", metricSummary);
        row.put("flakinessDashboard", buildFlakinessDashboard(metricSummary));
        row.put("defectCategorySummary", buildDefectCategorySummary(runResults));
        row.put("responsibilityBoundarySummary", buildResponsibilityBoundarySummary(runResults));
        row.put("scenarioSummaries", buildScenarioSummaries(runResults));
        row.put("experimentGroupSummaries", buildExperimentGroupSummaries(runResults));
        row.put("userProfileSummaries", buildUserProfileSummaries(runResults));
        row.put("scenarioFamilySummaries", buildScenarioFamilySummaries(runResults));
        return row;
    }

    private String buildMarkdown(
            String benchmarkName,
            List<SandboxPromptBenchmarkRunResult> runResults,
            Map<String, Object> jsonReport) {
        StringBuilder builder = new StringBuilder();
        builder.append("# ").append(benchmarkName).append("\n\n");
        builder.append("- benchmarkVersion: ").append(jsonReport.get("benchmarkVersion")).append('\n');
        builder.append("- generatedAt: ").append(jsonReport.get("generatedAt")).append('\n');
        builder.append("- runCount: ").append(runResults.size()).append("\n\n");
        builder.append("- observedPromptVersions: ").append(jsonReport.get("observedPromptVersions")).append('\n');
        builder.append("- observedContractVersions: ").append(jsonReport.get("observedContractVersions")).append('\n');
        builder.append("- observedTemplateKeys: ").append(jsonReport.get("observedTemplateKeys")).append('\n');
        builder.append("- observedUserProfileKeys: ").append(jsonReport.get("observedUserProfileKeys")).append('\n');
        builder.append("- observedScenarioFamilies: ").append(jsonReport.get("observedScenarioFamilies")).append("\n\n");

        builder.append("## Official Metric Coverage\n\n");
        @SuppressWarnings("unchecked")
        Map<String, Object> officialMetricCoverage = (Map<String, Object>) jsonReport.get("officialMetricCoverage");
        builder.append("- officialMetricTargetCount: ").append(officialMetricCoverage.get("officialMetricTargetCount")).append('\n');
        builder.append("- implementedOfficialMetricCount: ").append(officialMetricCoverage.get("implementedOfficialMetricCount")).append('\n');
        builder.append("- pendingOfficialMetricCount: ").append(officialMetricCoverage.get("pendingOfficialMetricCount")).append('\n');
        builder.append("- implementedOfficialMetrics: ").append(officialMetricCoverage.get("implementedOfficialMetrics")).append('\n');
        builder.append("- missingImplementedOfficialMetrics: ").append(officialMetricCoverage.get("missingImplementedOfficialMetrics")).append('\n');
        builder.append("- pendingOfficialMetrics: ").append(officialMetricCoverage.get("pendingOfficialMetrics")).append('\n');
        builder.append("- externalDecisionSummaryAvailable: ").append(officialMetricCoverage.get("externalDecisionSummaryAvailable")).append('\n');
        builder.append("- externalDecisionMetricNames: ").append(officialMetricCoverage.get("externalDecisionMetricNames")).append("\n\n");

        builder.append("## Metric Catalog\n\n");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> metricCatalog = (List<Map<String, Object>>) jsonReport.get("metricCatalog");
        for (Map<String, Object> metric : metricCatalog) {
            builder.append("- ")
                    .append(metric.get("metricCode"))
                    .append(" | ")
                    .append(metric.get("metricName"))
                    .append(" | category=")
                    .append(metric.get("category"))
                    .append(" | official=")
                    .append(metric.get("official"))
                    .append(" | implemented=")
                    .append(metric.get("implemented"))
                    .append('\n');
        }
        builder.append('\n');

        builder.append("## Metric Summary\n\n");
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> metricSummaries = (Map<String, Map<String, Object>>) jsonReport.get("metricSummaries");
        for (Map.Entry<String, Map<String, Object>> entry : metricSummaries.entrySet()) {
            builder.append("### ").append(entry.getKey()).append('\n');
            builder.append(String.format(Locale.ROOT,
                    "- successThreshold: %.2f (%s)%n- mean: %.2f%n- median: %.2f%n- stdDev: %.2f%n- p90: %.2f%n- p95: %.2f%n- p99: %.2f%n"
                            + "- min: %.2f%n- max: %.2f%n- failureRatePercent: %.2f%%%n- ci95: [%.2f, %.2f]%n"
                            + "- stabilityClass: %s%n- coefficientOfVariationPercent: %.2f%n%n",
                    entry.getValue().get("successThreshold"),
                    Boolean.TRUE.equals(entry.getValue().get("higherIsBetter")) ? "higher-is-better" : "lower-is-better",
                    entry.getValue().get("mean"),
                    entry.getValue().get("median"),
                    entry.getValue().get("stdDev"),
                    entry.getValue().get("p90"),
                    entry.getValue().get("p95"),
                    entry.getValue().get("p99"),
                    entry.getValue().get("min"),
                    entry.getValue().get("max"),
                    entry.getValue().get("failureRatePercent"),
                    entry.getValue().get("ci95Low"),
                    entry.getValue().get("ci95High"),
                    entry.getValue().get("stabilityClass"),
                    entry.getValue().get("coefficientOfVariationPercent")));
        }

        builder.append("## Flakiness Dashboard\n\n");
        @SuppressWarnings("unchecked")
        Map<String, Object> flakinessDashboard = (Map<String, Object>) jsonReport.get("flakinessDashboard");
        builder.append("- flakyMetricCount: ").append(flakinessDashboard.get("flakyMetricCount")).append('\n');
        builder.append("- variableMetricCount: ").append(flakinessDashboard.get("variableMetricCount")).append('\n');
        builder.append("- stableMetricCount: ").append(flakinessDashboard.get("stableMetricCount")).append("\n\n");

        builder.append("## Metric Drift\n\n");
        @SuppressWarnings("unchecked")
        Map<String, Object> metricDrift = (Map<String, Object>) jsonReport.get("metricDriftFromPreviousRun");
        builder.append("- previousRunAvailable: ").append(metricDrift.get("previousRunAvailable")).append('\n');
        builder.append("- improvedMetricCount: ").append(metricDrift.getOrDefault("improvedMetricCount", 0)).append('\n');
        builder.append("- regressedMetricCount: ").append(metricDrift.getOrDefault("regressedMetricCount", 0)).append("\n\n");

        builder.append("## Defect Summary\n\n");
        @SuppressWarnings("unchecked")
        Map<String, Object> defectSummary = (Map<String, Object>) jsonReport.get("defectCategorySummary");
        builder.append("- totalDefectCount: ").append(defectSummary.get("totalDefectCount")).append("\n");
        @SuppressWarnings("unchecked")
        Map<String, Long> categoryCounts = (Map<String, Long>) defectSummary.get("categoryCounts");
        if (categoryCounts.isEmpty()) {
            builder.append("- categoryCounts: none\n\n");
        } else {
            categoryCounts.forEach((category, count) ->
                    builder.append("- ").append(category).append(": ").append(count).append('\n'));
            builder.append('\n');
        }

        builder.append("## Responsibility Boundary\n\n");
        @SuppressWarnings("unchecked")
        Map<String, Object> responsibilityBoundary = (Map<String, Object>) jsonReport.get("responsibilityBoundarySummary");
        builder.append("- deterministicGateDefectCount: ").append(responsibilityBoundary.get("deterministicGateDefectCount")).append('\n');
        builder.append("- implementationDefectCount: ").append(responsibilityBoundary.get("implementationDefectCount")).append('\n');
        builder.append("- dataQualityDefectCount: ").append(responsibilityBoundary.get("dataQualityDefectCount")).append('\n');
        builder.append("- observabilityDefectCount: ").append(responsibilityBoundary.get("observabilityDefectCount")).append('\n');
        builder.append("- llmEvaluableGapCount: ").append(responsibilityBoundary.get("llmEvaluableGapCount")).append('\n');
        builder.append("- llmEvaluableZoneEnabled: ").append(responsibilityBoundary.get("llmEvaluableZoneEnabled")).append("\n\n");

        builder.append("## Scenario Summary\n\n");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> scenarioSummaries = (List<Map<String, Object>>) jsonReport.get("scenarioSummaries");
        for (Map<String, Object> scenarioSummary : scenarioSummaries) {
            builder.append("### ").append(scenarioSummary.get("scenarioKey")).append('\n');
            builder.append("- runCount: ").append(scenarioSummary.get("runCount")).append('\n');
            builder.append("- roundCountSet: ").append(scenarioSummary.get("roundCountSet")).append("\n\n");
        }

        builder.append("## Experiment Group Summary\n\n");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> experimentSummaries = (List<Map<String, Object>>) jsonReport.get("experimentGroupSummaries");
        for (Map<String, Object> experimentSummary : experimentSummaries) {
            builder.append("### ").append(experimentSummary.get("experimentGroup")).append('\n');
            builder.append("- runCount: ").append(experimentSummary.get("runCount")).append('\n');
            builder.append("- roundCountSet: ").append(experimentSummary.get("roundCountSet")).append("\n\n");
        }

        builder.append("## User Profile Summary\n\n");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> userProfileSummaries = (List<Map<String, Object>>) jsonReport.get("userProfileSummaries");
        for (Map<String, Object> userProfileSummary : userProfileSummaries) {
            builder.append("### ").append(userProfileSummary.get("userProfileKey")).append('\n');
            builder.append("- runCount: ").append(userProfileSummary.get("runCount")).append('\n');
            builder.append("- scenarioFamilies: ").append(userProfileSummary.get("scenarioFamilies")).append("\n\n");
        }

        builder.append("## Scenario Family Summary\n\n");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> scenarioFamilySummaries = (List<Map<String, Object>>) jsonReport.get("scenarioFamilySummaries");
        for (Map<String, Object> scenarioFamilySummary : scenarioFamilySummaries) {
            builder.append("### ").append(scenarioFamilySummary.get("scenarioFamily")).append('\n');
            builder.append("- runCount: ").append(scenarioFamilySummary.get("runCount")).append('\n');
            builder.append("- userProfileKeys: ").append(scenarioFamilySummary.get("userProfileKeys")).append("\n\n");
        }

        builder.append("## Run Ledger\n\n");
        for (SandboxPromptBenchmarkRunResult result : runResults) {
            builder.append("### ").append(result.benchmarkRunId()).append('\n');
            builder.append("- username: ").append(result.username()).append('\n');
            builder.append("- scenarioKey: ").append(result.replayRun().scenarioKey()).append('\n');
            builder.append("- experimentGroup: ").append(result.replayRun().experimentGroup()).append('\n');
            builder.append("- roundCount: ").append(result.replayRun().rounds().size()).append('\n');
            builder.append("- roundPassRates: ").append(result.roundScorecards().stream()
                    .map(scorecard -> String.format(Locale.ROOT, "%.2f", scorecard.passRatePercent()))
                    .toList()).append('\n');
            builder.append("- traceContractPassRates: ").append(result.traceContractAssessments().stream()
                    .map(assessment -> String.format(Locale.ROOT, "%.2f", assessment.complianceRate()))
                    .toList()).append('\n');
            builder.append("- promptFidelityRates: ").append(result.promptFidelityAssessments().stream()
                    .map(assessment -> String.format(Locale.ROOT, "%.2f", assessment.fidelityRate()))
                    .toList()).append('\n');
            builder.append("- artifactIntegrityRates: ").append(result.artifactIntegrityAssessments().stream()
                    .map(assessment -> String.format(Locale.ROOT, "%.2f", assessment.integrityRate()))
                    .toList()).append('\n');
            builder.append(String.format(Locale.ROOT,
                    "- progressionPassRate: %.2f%n",
                    result.progressionScorecard().passRatePercent()));
            builder.append("- defectCount: ").append(result.defectFindings().size()).append('\n');
            builder.append("- metrics:\n");
            result.metrics().forEach((metricName, value) ->
                    builder.append(String.format(Locale.ROOT, "  - %s: %.2f%n", metricName, value)));
            if (!result.defectFindings().isEmpty()) {
                builder.append("- defects:\n");
                result.defectFindings().forEach(finding ->
                        builder.append("  - [")
                                .append(finding.category().name())
                                .append("] ")
                                .append(finding.code())
                                .append(" | ")
                                .append(finding.summary())
                                .append(" | ")
                                .append(finding.detail())
                                .append('\n'));
            }
            builder.append('\n');
        }

        return builder.toString();
    }

    private String buildHtml(String benchmarkName, Map<String, Object> jsonReport) {
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> metricSummaries =
                (Map<String, Map<String, Object>>) jsonReport.get("metricSummaries");
        @SuppressWarnings("unchecked")
        Map<String, Object> officialCoverage =
                (Map<String, Object>) jsonReport.get("officialMetricCoverage");

        StringBuilder builder = new StringBuilder();
        builder.append("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">")
                .append("<title>").append(escapeHtml(benchmarkName)).append("</title>")
                .append("<style>")
                .append("body{font-family:'Segoe UI',sans-serif;margin:32px;color:#111827;background:#f9fafb;}")
                .append("h1,h2{color:#111827;}table{border-collapse:collapse;width:100%;margin:16px 0;}")
                .append("th,td{border:1px solid #d1d5db;padding:8px;text-align:left;font-size:14px;}")
                .append("th{background:#eef2ff;}code{background:#e5e7eb;padding:2px 4px;border-radius:4px;}")
                .append("a{color:#2563eb;text-decoration:none;}ul{line-height:1.6;}")
                .append("</style></head><body>");
        builder.append("<h1>").append(escapeHtml(benchmarkName)).append("</h1>");
        builder.append("<p>Generated at ").append(escapeHtml(String.valueOf(jsonReport.get("generatedAt")))).append("</p>");
        builder.append("<ul>");
        builder.append("<li>Benchmark version: <code>").append(escapeHtml(String.valueOf(jsonReport.get("benchmarkVersion")))).append("</code></li>");
        builder.append("<li>Run count: ").append(escapeHtml(String.valueOf(jsonReport.get("runCount")))).append("</li>");
        builder.append("<li>Implemented official metrics: ").append(escapeHtml(String.valueOf(officialCoverage.get("implementedOfficialMetricCount")))).append("</li>");
        builder.append("<li>Pending official metrics: ").append(escapeHtml(String.valueOf(officialCoverage.get("pendingOfficialMetricCount")))).append("</li>");
        builder.append("</ul>");
        builder.append("<p>")
                .append("<a href=\"summary.json\">summary.json</a> | ")
                .append("<a href=\"summary.md\">summary.md</a> | ")
                .append("<a href=\"runs.ndjson\">runs.ndjson</a> | ")
                .append("<a href=\"rounds.ndjson\">rounds.ndjson</a> | ")
                .append("<a href=\"metrics.ndjson\">metrics.ndjson</a> | ")
                .append("<a href=\"defects.ndjson\">defects.ndjson</a> | ")
                .append("<a href=\"decision-summary.html\">decision summary</a> | ")
                .append("<a href=\"decision-index.html\">decision index</a> | ")
                .append("<a href=\"compression/compression-summary.html\">compression evidence</a> | ")
                .append("<a href=\"compression-impact/compression-impact-summary.html\">compression impact</a>")
                .append("</p>");
        builder.append("<h2>Metric Summary</h2><table><thead><tr>")
                .append("<th>Metric</th><th>Mean</th><th>Failure Rate</th><th>95% CI</th><th>Stability</th></tr>")
                .append("</thead><tbody>");
        for (Map.Entry<String, Map<String, Object>> entry : metricSummaries.entrySet()) {
            Map<String, Object> summary = entry.getValue();
            builder.append("<tr><td>").append(escapeHtml(entry.getKey())).append("</td>")
                    .append("<td>").append(formatNumber(summary.get("mean"))).append("</td>")
                    .append("<td>").append(formatNumber(summary.get("failureRatePercent"))).append("%</td>")
                    .append("<td>[")
                    .append(formatNumber(summary.get("ci95Low")))
                    .append(", ")
                    .append(formatNumber(summary.get("ci95High")))
                    .append("]</td>")
                    .append("<td>").append(escapeHtml(String.valueOf(summary.get("stabilityClass")))).append("</td></tr>");
        }
        builder.append("</tbody></table></body></html>");
        return builder.toString();
    }

    private void writeNdjson(Path outputPath, List<Map<String, Object>> rows) throws IOException {
        StringBuilder builder = new StringBuilder();
        for (Map<String, Object> row : rows) {
            builder.append(objectMapper.writeValueAsString(row)).append('\n');
        }
        Files.writeString(outputPath, builder.toString());
    }

    private void cleanCurrentReportFiles() throws IOException {
        List<String> fileNames = List.of(
                "summary.json",
                "summary.md",
                "summary.html",
                "runs.ndjson",
                "rounds.ndjson",
                "metrics.ndjson",
                "prompt-fidelity.ndjson",
                "defects.ndjson",
                "scenarios.ndjson",
                "experiment-groups.ndjson",
                "user-profiles.ndjson",
                "scenario-families.ndjson",
                "metric-catalog.ndjson",
                "latest-history.json");
        for (String fileName : fileNames) {
            Files.deleteIfExists(reportDirectory.resolve(fileName));
        }
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

    private Map<String, Object> readPreviousHistoryRow() throws IOException {
        Path latestHistoryPath = reportDirectory.resolve("latest-history.json");
        if (!Files.exists(latestHistoryPath)) {
            return Map.of();
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> history = objectMapper.readValue(Files.readString(latestHistoryPath), Map.class);
        return history == null ? Map.of() : history;
    }

    private void appendNdjson(Path outputPath, Map<String, Object> row) throws IOException {
        String serialized = objectMapper.writeValueAsString(row) + System.lineSeparator();
        if (Files.exists(outputPath)) {
            Files.writeString(outputPath, serialized, StandardOpenOption.APPEND);
        } else {
            Files.writeString(outputPath, serialized);
        }
    }

    private int safeSize(List<?> values) {
        return values == null ? 0 : values.size();
    }

    private String classifyStability(SandboxPromptBenchmarkStatistics.Summary summary, boolean higherIsBetter) {
        if (summary == null || summary.sampleCount() <= 1) {
            return "STABLE";
        }
        if (summary.failureRatePercent() > 0.0d) {
            return "FLAKY";
        }
        double coefficientOfVariation = coefficientOfVariationPercent(summary);
        if (coefficientOfVariation >= 5.0d || summary.stdDev() >= 3.0d) {
            return "VARIABLE";
        }
        if (!higherIsBetter && summary.max() > 0.0d) {
            return "VARIABLE";
        }
        return "STABLE";
    }

    private double coefficientOfVariationPercent(SandboxPromptBenchmarkStatistics.Summary summary) {
        if (summary == null) {
            return 0.0d;
        }
        double meanAbs = Math.abs(summary.mean());
        if (meanAbs < 0.000001d) {
            return 0.0d;
        }
        return (summary.stdDev() / meanAbs) * 100.0d;
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
}
