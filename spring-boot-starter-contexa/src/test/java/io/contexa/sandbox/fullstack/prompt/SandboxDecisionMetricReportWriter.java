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

public final class SandboxDecisionMetricReportWriter {

    private static final List<double[]> CALIBRATION_BUCKETS = List.of(
            new double[]{0.00d, 0.20d},
            new double[]{0.20d, 0.40d},
            new double[]{0.40d, 0.60d},
            new double[]{0.60d, 0.80d},
            new double[]{0.80d, 1.01d});

    private final ObjectMapper objectMapper;
    private final Path reportDirectory;

    public SandboxDecisionMetricReportWriter(ObjectMapper objectMapper, Path reportDirectory) {
        this.objectMapper = objectMapper;
        this.reportDirectory = reportDirectory;
    }

    public void write(SandboxDecisionMetric metric, List<SandboxDecisionBenchmarkRunResult> runResults) {
        try {
            Files.createDirectories(reportDirectory);
            Path metricDirectory = reportDirectory.resolve(metric.key());
            Files.createDirectories(metricDirectory);

            List<Double> values = runResults.stream()
                    .map(run -> run.metrics().get(metric.key()))
                    .filter(value -> value != null)
                    .toList();
            SandboxPromptBenchmarkStatistics.Summary summary =
                    SandboxPromptBenchmarkStatistics.summarize(values, metric.successThreshold(), metric.higherIsBetter());

            Map<String, Object> summaryPayload = summaryPayload(metric, summary, runResults);
            List<Map<String, Object>> runRows = runRows(metric, runResults);
            List<Map<String, Object>> roundRows = roundRows(metric, runResults);
            List<Map<String, Object>> defectRows = defectRows(metric, runResults);
            List<Map<String, Object>> calibrationRows = calibrationRows(runResults);
            List<Map<String, Object>> adjudicationRows = adjudicationRows(metric, runResults);
            List<Map<String, Object>> reviewerAgreementRows = reviewerAgreementRows(metric, runResults);

            writeJson(metricDirectory.resolve(metric.key() + "-summary.json"), summaryPayload);
            writeMarkdown(metricDirectory.resolve(metric.key() + "-summary.md"), markdownSummary(metric, summary, runResults));
            writeHtml(metricDirectory.resolve(metric.key() + "-summary.html"), buildMetricHtml(metric, summaryPayload));
            writeJson(metricDirectory.resolve(metric.key() + "-calibration.json"), calibrationPayload(metric, calibrationRows));
            writeHtml(metricDirectory.resolve(metric.key() + "-calibration.html"), buildCalibrationHtml(metric, calibrationRows));
            writeNdjson(metricDirectory.resolve(metric.key() + "-runs.ndjson"), runRows);
            writeNdjson(metricDirectory.resolve(metric.key() + "-rounds.ndjson"), roundRows);
            writeNdjson(metricDirectory.resolve(metric.key() + "-defects.ndjson"), defectRows);
            writeNdjson(metricDirectory.resolve(metric.key() + "-adjudication.ndjson"), adjudicationRows);
            writeNdjson(metricDirectory.resolve(metric.key() + "-reviewer-agreement.ndjson"), reviewerAgreementRows);

            writeDecisionIndexHtml();
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to write sandbox decision metric report: " + metric.key(), exception);
        }
    }

    public void writeAll(List<SandboxDecisionBenchmarkRunResult> runResults) {
        for (SandboxDecisionMetric metric : SandboxDecisionMetric.values()) {
            write(metric, runResults);
        }
    }

    private Map<String, Object> summaryPayload(
            SandboxDecisionMetric metric,
            SandboxPromptBenchmarkStatistics.Summary summary,
            List<SandboxDecisionBenchmarkRunResult> runResults) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("metricKey", metric.key());
        payload.put("metricName", metric.displayName());
        payload.put("generatedAt", Instant.now().toString());
        payload.put("realLlmMode", SandboxDecisionBenchmarkSettings.useRealLlm());
        payload.put("boundaryMode", SandboxDecisionBenchmarkSettings.boundaryMode());
        payload.put("modelId", SandboxDecisionBenchmarkSettings.pinnedModelId());
        payload.put("goldVersion", SandboxDecisionBenchmarkSettings.goldVersion());
        payload.put("adjudicationVersion", SandboxDecisionBenchmarkSettings.adjudicationVersion());
        payload.put("successThreshold", metric.successThreshold());
        payload.put("sampleCount", summary.sampleCount());
        payload.put("mean", summary.mean());
        payload.put("median", summary.median());
        payload.put("stdDev", summary.stdDev());
        payload.put("min", summary.min());
        payload.put("max", summary.max());
        payload.put("failureRatePercent", summary.failureRatePercent());
        payload.put("ci95Low", summary.ci95Low());
        payload.put("ci95High", summary.ci95High());
        payload.put("runCount", runResults.size());
        payload.put("scenarioKeys", runResults.stream().map(run -> run.replayRun().scenarioKey()).distinct().toList());
        payload.put("scenarioFamilies", runResults.stream().map(run -> run.replayRun().scenario().scenarioFamily()).distinct().toList());
        payload.put("decisionScenarioSelector", SandboxDecisionBenchmarkSettings.scenarioSelector());
        payload.put("reportFiles", Map.of(
                "summaryJson", metric.key() + "-summary.json",
                "summaryMd", metric.key() + "-summary.md",
                "summaryHtml", metric.key() + "-summary.html",
                "calibrationJson", metric.key() + "-calibration.json",
                "calibrationHtml", metric.key() + "-calibration.html",
                "runsNdjson", metric.key() + "-runs.ndjson",
                "roundsNdjson", metric.key() + "-rounds.ndjson",
                "defectsNdjson", metric.key() + "-defects.ndjson",
                "adjudicationNdjson", metric.key() + "-adjudication.ndjson",
                "reviewerAgreementNdjson", metric.key() + "-reviewer-agreement.ndjson"));
        return payload;
    }

    private Map<String, Object> calibrationPayload(
            SandboxDecisionMetric metric,
            List<Map<String, Object>> calibrationRows) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("metricKey", metric.key());
        payload.put("metricName", metric.displayName());
        payload.put("generatedAt", Instant.now().toString());
        payload.put("modelId", SandboxDecisionBenchmarkSettings.pinnedModelId());
        payload.put("boundaryMode", SandboxDecisionBenchmarkSettings.boundaryMode());
        payload.put("goldVersion", SandboxDecisionBenchmarkSettings.goldVersion());
        payload.put("adjudicationVersion", SandboxDecisionBenchmarkSettings.adjudicationVersion());
        payload.put("buckets", calibrationRows);
        return payload;
    }

    private String markdownSummary(
            SandboxDecisionMetric metric,
            SandboxPromptBenchmarkStatistics.Summary summary,
            List<SandboxDecisionBenchmarkRunResult> runResults) {
        return String.format(Locale.ROOT, """
                # %s

                - metricKey: `%s`
                - boundaryMode: `%s`
                - modelId: `%s`
                - goldVersion: `%s`
                - adjudicationVersion: `%s`
                - scenarioSelector: `%s`
                - sampleCount: `%d`
                - mean: `%.3f`
                - median: `%.3f`
                - stdDev: `%.3f`
                - min/max: `%.3f / %.3f`
                - failureRatePercent: `%.3f`
                - ci95: `[%.3f, %.3f]`
                - runCount: `%d`
                - scenarioFamilies: `%s`
                """,
                metric.displayName(),
                metric.key(),
                SandboxDecisionBenchmarkSettings.boundaryMode(),
                SandboxDecisionBenchmarkSettings.pinnedModelId(),
                SandboxDecisionBenchmarkSettings.goldVersion(),
                SandboxDecisionBenchmarkSettings.adjudicationVersion(),
                SandboxDecisionBenchmarkSettings.scenarioSelector(),
                summary.sampleCount(),
                summary.mean(),
                summary.median(),
                summary.stdDev(),
                summary.min(),
                summary.max(),
                summary.failureRatePercent(),
                summary.ci95Low(),
                summary.ci95High(),
                runResults.size(),
                runResults.stream().map(run -> run.replayRun().scenario().scenarioFamily()).distinct().toList());
    }

    private List<Map<String, Object>> runRows(SandboxDecisionMetric metric, List<SandboxDecisionBenchmarkRunResult> runResults) {
        return runResults.stream().map(run -> {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("metricKey", metric.key());
            row.put("benchmarkRunId", run.benchmarkRunId());
            row.put("username", run.username());
            row.put("scenarioKey", run.replayRun().scenarioKey());
            row.put("scenarioFamily", run.replayRun().scenario().scenarioFamily());
            row.put("metricValue", run.metrics().get(metric.key()));
            row.put("roundCount", run.roundResults().size());
            row.put("boundaryMode", SandboxDecisionBenchmarkSettings.boundaryMode());
            row.put("modelId", SandboxDecisionBenchmarkSettings.pinnedModelId());
            return row;
        }).toList();
    }

    private List<Map<String, Object>> roundRows(SandboxDecisionMetric metric, List<SandboxDecisionBenchmarkRunResult> runResults) {
        return runResults.stream()
                .flatMap(run -> run.roundResults().stream())
                .map(round -> {
                    SandboxDecisionTraceSnapshot decisionSnapshot = round.replayRound() != null
                            ? round.replayRound().decisionSnapshot()
                            : null;
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("metricKey", metric.key());
                    row.put("benchmarkRunId", round.benchmarkRunId());
                    row.put("username", round.username());
                    row.put("scenarioKey", round.scenarioKey());
                    row.put("scenarioFamily", round.scenarioFamily());
                    row.put("roundNumber", round.roundNumber());
                    row.put("roundKey", round.roundKey());
                    row.put("predictedAction", round.predictedAction());
                    row.put("predictedConfidence", round.predictedConfidence());
                    row.put("uncertaintyRequired", round.goldCase().uncertaintyRequired());
                    row.put("safeActions", round.goldCase().safeActions());
                    row.put("unsafeActions", round.goldCase().unsafeActions());
                    row.put("confidenceBand", round.goldCase().confidenceBand().pretty());
                    row.put("requiredEvidenceTokens", round.goldCase().requiredEvidenceTokens());
                    row.put("groundedClaimPrecision", round.adjudication().groundedClaimPrecision());
                    row.put("unsupportedClaimRate", round.adjudication().unsupportedClaimRate());
                    row.put("contradictedClaimRate", round.adjudication().contradictedClaimRate());
                    row.put("uncertaintyLanguagePresent", round.adjudication().uncertaintyLanguagePresent());
                    row.put("requiredEvidenceCovered", round.adjudication().requiredEvidenceCovered());
                    row.put("actionAllowedByGoldCase", round.actionAllowedByGoldCase());
                    row.put("confidenceWithinBand", round.confidenceWithinBand());
                    row.put("unsafeOverconfidence", round.unsafeOverconfidence());
                    row.put("safeUncertaintyPass", round.safeUncertaintyPass());
                    row.put("decisionStatus", decisionStatus(decisionSnapshot));
                    row.put("decisionErrorType", decisionErrorType(decisionSnapshot));
                    row.put("decisionErrorMessage", decisionErrorMessage(decisionSnapshot));
                    row.put("rawResponsePreview", responsePreview(decisionSnapshot));
                    row.put("structuredOutputComplete", structuredOutputComplete(decisionSnapshot));
                    row.put("metricValue", metricValue(metric, round));
                    return row;
                }).toList();
    }

    private List<Map<String, Object>> defectRows(SandboxDecisionMetric metric, List<SandboxDecisionBenchmarkRunResult> runResults) {
        return runResults.stream()
                .flatMap(run -> run.roundResults().stream())
                .filter(round -> metricFailure(metric, round))
                .map(round -> {
                    SandboxDecisionTraceSnapshot decisionSnapshot = round.replayRound() != null
                            ? round.replayRound().decisionSnapshot()
                            : null;
                    Map<String, Object> defect = new LinkedHashMap<>();
                    defect.put("metricKey", metric.key());
                    defect.put("benchmarkRunId", round.benchmarkRunId());
                    defect.put("username", round.username());
                    defect.put("scenarioKey", round.scenarioKey());
                    defect.put("scenarioFamily", round.scenarioFamily());
                    defect.put("roundNumber", round.roundNumber());
                    defect.put("roundKey", round.roundKey());
                    defect.put("predictedAction", round.predictedAction());
                    defect.put("predictedConfidence", round.predictedConfidence());
                    defect.put("reasoning", round.predictedReasoning());
                    defect.put("safeActions", round.goldCase().safeActions());
                    defect.put("confidenceBand", round.goldCase().confidenceBand().pretty());
                    defect.put("requiredEvidenceTokens", round.goldCase().requiredEvidenceTokens());
                    defect.put("groundedClaimPrecision", round.adjudication().groundedClaimPrecision());
                    defect.put("unsupportedClaimRate", round.adjudication().unsupportedClaimRate());
                    defect.put("contradictedClaimRate", round.adjudication().contradictedClaimRate());
                    defect.put("unsafeOverconfidence", round.unsafeOverconfidence());
                    defect.put("safeUncertaintyPass", round.safeUncertaintyPass());
                    defect.put("decisionStatus", decisionStatus(decisionSnapshot));
                    defect.put("decisionErrorType", decisionErrorType(decisionSnapshot));
                    defect.put("decisionErrorMessage", decisionErrorMessage(decisionSnapshot));
                    defect.put("rawResponsePreview", responsePreview(decisionSnapshot));
                    defect.put("structuredOutputComplete", structuredOutputComplete(decisionSnapshot));
                    defect.put("metricValue", metricValue(metric, round));
                    defect.put("defectReason", defectReason(metric, round));
                    return defect;
                }).toList();
    }

    private List<Map<String, Object>> calibrationRows(List<SandboxDecisionBenchmarkRunResult> runResults) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (double[] bucket : CALIBRATION_BUCKETS) {
            double lowInclusive = bucket[0];
            double highExclusive = bucket[1];
            List<SandboxDecisionRoundResult> bucketRounds = runResults.stream()
                    .flatMap(run -> run.roundResults().stream())
                    .filter(round -> inBucket(round.predictedConfidence(), lowInclusive, highExclusive))
                    .toList();

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("bucketLabel", String.format(Locale.ROOT, "[%.2f, %.2f)", lowInclusive, Math.min(1.0d, highExclusive)));
            row.put("confidenceLowInclusive", lowInclusive);
            row.put("confidenceHighExclusive", Math.min(1.0d, highExclusive));
            row.put("roundCount", bucketRounds.size());
            row.put("meanPredictedConfidence", average(bucketRounds.stream()
                    .map(SandboxDecisionRoundResult::predictedConfidence)
                    .filter(java.util.Objects::nonNull)
                    .mapToDouble(Double::doubleValue)
                    .toArray()));
            row.put("actionAllowedRate", average(bucketRounds.stream()
                    .mapToDouble(round -> round.actionAllowedByGoldCase() ? 100.0d : 0.0d)
                    .toArray()));
            row.put("confidenceWithinBandRate", average(bucketRounds.stream()
                    .mapToDouble(round -> round.confidenceWithinBand() ? 100.0d : 0.0d)
                    .toArray()));
            row.put("unsafeOverconfidenceRate", average(bucketRounds.stream()
                    .mapToDouble(round -> round.unsafeOverconfidence() ? 100.0d : 0.0d)
                    .toArray()));
            row.put("safeUncertaintyPassRate", average(bucketRounds.stream()
                    .mapToDouble(round -> round.safeUncertaintyPass() ? 100.0d : 0.0d)
                    .toArray()));
            rows.add(row);
        }
        return rows;
    }

    private List<Map<String, Object>> adjudicationRows(SandboxDecisionMetric metric, List<SandboxDecisionBenchmarkRunResult> runResults) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (SandboxDecisionBenchmarkRunResult runResult : runResults) {
            for (SandboxDecisionRoundResult round : runResult.roundResults()) {
                List<SandboxDecisionClaimAssessment> claims = round.adjudication().claimAssessments();
                if (claims.isEmpty()) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("metricKey", metric.key());
                    row.put("benchmarkRunId", round.benchmarkRunId());
                    row.put("scenarioKey", round.scenarioKey());
                    row.put("scenarioFamily", round.scenarioFamily());
                    row.put("roundNumber", round.roundNumber());
                    row.put("roundKey", round.roundKey());
                    row.put("claimIndex", 0);
                    row.put("claimText", null);
                    row.put("verdict", "NO_CLAIMS");
                    row.put("evidenceNote", "Reasoning did not yield claim segments.");
                    row.put("requiredEvidenceCovered", round.adjudication().requiredEvidenceCovered());
                    rows.add(row);
                    continue;
                }
                for (int claimIndex = 0; claimIndex < claims.size(); claimIndex++) {
                    SandboxDecisionClaimAssessment claim = claims.get(claimIndex);
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("metricKey", metric.key());
                    row.put("benchmarkRunId", round.benchmarkRunId());
                    row.put("scenarioKey", round.scenarioKey());
                    row.put("scenarioFamily", round.scenarioFamily());
                    row.put("roundNumber", round.roundNumber());
                    row.put("roundKey", round.roundKey());
                    row.put("claimIndex", claimIndex + 1);
                    row.put("claimText", claim.claim());
                    row.put("verdict", claim.verdict().name());
                    row.put("evidenceNote", claim.rationale());
                    row.put("requiredEvidenceCovered", round.adjudication().requiredEvidenceCovered());
                    rows.add(row);
                }
            }
        }
        return rows;
    }

    private List<Map<String, Object>> reviewerAgreementRows(SandboxDecisionMetric metric, List<SandboxDecisionBenchmarkRunResult> runResults) {
        return runResults.stream()
                .flatMap(run -> run.roundResults().stream())
                .map(round -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("metricKey", metric.key());
                    row.put("benchmarkRunId", round.benchmarkRunId());
                    row.put("scenarioKey", round.scenarioKey());
                    row.put("scenarioFamily", round.scenarioFamily());
                    row.put("roundNumber", round.roundNumber());
                    row.put("roundKey", round.roundKey());
                    row.put("reviewerPair", "GOLD_POLICY::AUTO_ADJUDICATOR");
                    row.put("agreementState", automatedAgreementState(metric, round));
                    row.put("manualReviewRequired", metricFailure(metric, round));
                    row.put("predictedAction", round.predictedAction());
                    row.put("safeActions", round.goldCase().safeActions());
                    row.put("predictedConfidence", round.predictedConfidence());
                    row.put("confidenceBand", round.goldCase().confidenceBand().pretty());
                    row.put("groundedClaimPrecision", round.adjudication().groundedClaimPrecision());
                    row.put("unsupportedClaimRate", round.adjudication().unsupportedClaimRate());
                    row.put("contradictedClaimRate", round.adjudication().contradictedClaimRate());
                    row.put("safeUncertaintyPass", round.safeUncertaintyPass());
                    row.put("agreementNotes", automatedAgreementNotes(metric, round));
                    return row;
                }).toList();
    }

    private void writeDecisionIndexHtml() throws IOException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">")
                .append("<title>Sandbox Decision Benchmark Index</title>")
                .append("<style>")
                .append("body{font-family:'Segoe UI',sans-serif;margin:32px;color:#1f2937;}")
                .append("table{border-collapse:collapse;width:100%;margin-top:16px;}")
                .append("th,td{border:1px solid #d1d5db;padding:8px;text-align:left;}")
                .append("th{background:#f3f4f6;}a{color:#2563eb;text-decoration:none;}")
                .append("</style></head><body>");
        builder.append("<h1>Sandbox Decision Benchmark Index</h1>");
        builder.append("<p>Generated at ").append(escapeHtml(Instant.now().toString())).append("</p>");
        builder.append("<p>boundaryMode=").append(escapeHtml(SandboxDecisionBenchmarkSettings.boundaryMode()))
                .append(" | modelId=").append(escapeHtml(SandboxDecisionBenchmarkSettings.pinnedModelId()))
                .append(" | scenarioSelector=").append(escapeHtml(SandboxDecisionBenchmarkSettings.scenarioSelector()))
                .append("</p>");
        builder.append("<table><thead><tr><th>Metric</th><th>Summary</th><th>Calibration</th><th>Runs</th><th>Rounds</th><th>Defects</th><th>Adjudication</th><th>Reviewer Agreement</th></tr></thead><tbody>");
        for (SandboxDecisionMetric metric : SandboxDecisionMetric.values()) {
            String key = metric.key();
            builder.append("<tr><td>").append(escapeHtml(metric.displayName())).append("</td>")
                    .append("<td><a href=\"").append(key).append("/").append(key).append("-summary.html\">")
                    .append(key).append("-summary.html</a></td>")
                    .append("<td><a href=\"").append(key).append("/").append(key).append("-calibration.html\">")
                    .append(key).append("-calibration.html</a></td>")
                    .append("<td><a href=\"").append(key).append("/").append(key).append("-runs.ndjson\">runs</a></td>")
                    .append("<td><a href=\"").append(key).append("/").append(key).append("-rounds.ndjson\">rounds</a></td>")
                    .append("<td><a href=\"").append(key).append("/").append(key).append("-defects.ndjson\">defects</a></td>")
                    .append("<td><a href=\"").append(key).append("/").append(key).append("-adjudication.ndjson\">adjudication</a></td>")
                    .append("<td><a href=\"").append(key).append("/").append(key).append("-reviewer-agreement.ndjson\">reviewer agreement</a></td></tr>");
        }
        builder.append("</tbody></table></body></html>");
        Files.writeString(reportDirectory.resolve("decision-index.html"), builder.toString());
    }

    private String buildMetricHtml(SandboxDecisionMetric metric, Map<String, Object> summaryPayload) {
        StringBuilder builder = new StringBuilder();
        builder.append("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">")
                .append("<title>").append(escapeHtml(metric.displayName())).append("</title>")
                .append("<style>")
                .append("body{font-family:'Segoe UI',sans-serif;margin:32px;color:#1f2937;}")
                .append("table{border-collapse:collapse;width:100%;margin-top:16px;}")
                .append("th,td{border:1px solid #d1d5db;padding:8px;text-align:left;}")
                .append("th{background:#f3f4f6;}a{color:#2563eb;text-decoration:none;}")
                .append("</style></head><body>");
        builder.append("<h1>").append(escapeHtml(metric.displayName())).append("</h1>");
        builder.append("<p>metricKey=").append(escapeHtml(metric.key()))
                .append(" | boundaryMode=").append(escapeHtml(String.valueOf(summaryPayload.get("boundaryMode"))))
                .append(" | modelId=").append(escapeHtml(String.valueOf(summaryPayload.get("modelId"))))
                .append("</p>");
        builder.append("<ul>")
                .append("<li>mean: ").append(format(summaryPayload.get("mean"))).append("</li>")
                .append("<li>failureRatePercent: ").append(format(summaryPayload.get("failureRatePercent"))).append("</li>")
                .append("<li>ci95: [").append(format(summaryPayload.get("ci95Low"))).append(", ")
                .append(format(summaryPayload.get("ci95High"))).append("]</li>")
                .append("<li>goldVersion: ").append(escapeHtml(String.valueOf(summaryPayload.get("goldVersion")))).append("</li>")
                .append("<li>adjudicationVersion: ").append(escapeHtml(String.valueOf(summaryPayload.get("adjudicationVersion")))).append("</li>")
                .append("</ul>");
        builder.append("<p><a href=\"").append(metric.key()).append("-summary.json\">summary.json</a> | ")
                .append("<a href=\"").append(metric.key()).append("-summary.md\">summary.md</a> | ")
                .append("<a href=\"").append(metric.key()).append("-calibration.html\">calibration</a> | ")
                .append("<a href=\"").append(metric.key()).append("-runs.ndjson\">runs</a> | ")
                .append("<a href=\"").append(metric.key()).append("-rounds.ndjson\">rounds</a> | ")
                .append("<a href=\"").append(metric.key()).append("-defects.ndjson\">defects</a> | ")
                .append("<a href=\"").append(metric.key()).append("-adjudication.ndjson\">adjudication</a> | ")
                .append("<a href=\"").append(metric.key()).append("-reviewer-agreement.ndjson\">reviewer agreement</a></p>")
                .append("<p><a href=\"../decision-index.html\">decision-index.html</a></p>");
        builder.append("</body></html>");
        return builder.toString();
    }

    private String buildCalibrationHtml(SandboxDecisionMetric metric, List<Map<String, Object>> calibrationRows) {
        StringBuilder builder = new StringBuilder();
        builder.append("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">")
                .append("<title>").append(escapeHtml(metric.displayName())).append(" Calibration</title>")
                .append("<style>")
                .append("body{font-family:'Segoe UI',sans-serif;margin:32px;color:#1f2937;}")
                .append("table{border-collapse:collapse;width:100%;margin-top:16px;}")
                .append("th,td{border:1px solid #d1d5db;padding:8px;text-align:left;}")
                .append("th{background:#f3f4f6;}a{color:#2563eb;text-decoration:none;}")
                .append("</style></head><body>");
        builder.append("<h1>").append(escapeHtml(metric.displayName())).append(" Calibration</h1>");
        builder.append("<p><a href=\"").append(metric.key()).append("-calibration.json\">calibration.json</a> | ")
                .append("<a href=\"").append(metric.key()).append("-summary.html\">summary</a></p>");
        builder.append("<table><thead><tr><th>Bucket</th><th>Rounds</th><th>Mean Confidence</th><th>Allowed Rate</th><th>Band Pass</th><th>Unsafe Overconfidence</th><th>Safe Uncertainty</th></tr></thead><tbody>");
        for (Map<String, Object> row : calibrationRows) {
            builder.append("<tr><td>").append(escapeHtml(String.valueOf(row.get("bucketLabel")))).append("</td>")
                    .append("<td>").append(row.get("roundCount")).append("</td>")
                    .append("<td>").append(format(row.get("meanPredictedConfidence"))).append("</td>")
                    .append("<td>").append(format(row.get("actionAllowedRate"))).append("</td>")
                    .append("<td>").append(format(row.get("confidenceWithinBandRate"))).append("</td>")
                    .append("<td>").append(format(row.get("unsafeOverconfidenceRate"))).append("</td>")
                    .append("<td>").append(format(row.get("safeUncertaintyPassRate"))).append("</td></tr>");
        }
        builder.append("</tbody></table></body></html>");
        return builder.toString();
    }

    private boolean metricFailure(SandboxDecisionMetric metric, SandboxDecisionRoundResult round) {
        return metricValue(metric, round) < metric.successThreshold();
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
            case CDC -> "actionAllowed=%s, confidenceWithinBand=%s, unsafeOverconfidence=%s"
                    .formatted(round.actionAllowedByGoldCase(), round.confidenceWithinBand(), round.unsafeOverconfidence());
            case ERA -> "groundedClaimPrecision=%s, unsupportedClaimRate=%s, contradictedClaimRate=%s, requiredEvidenceCovered=%s"
                    .formatted(
                            format(round.adjudication().groundedClaimPrecision()),
                            format(round.adjudication().unsupportedClaimRate()),
                            format(round.adjudication().contradictedClaimRate()),
                            round.adjudication().requiredEvidenceCovered());
            case SUHR -> "uncertaintyRequired=%s, safeUncertaintyPass=%s, unsafeOverconfidence=%s"
                    .formatted(round.goldCase().uncertaintyRequired(), round.safeUncertaintyPass(), round.unsafeOverconfidence());
        };
    }

    private String automatedAgreementState(SandboxDecisionMetric metric, SandboxDecisionRoundResult round) {
        return metricFailure(metric, round) ? "REVIEW_REQUIRED" : "AGREE";
    }

    private String automatedAgreementNotes(SandboxDecisionMetric metric, SandboxDecisionRoundResult round) {
        return switch (metric) {
            case CDC -> round.actionAllowedByGoldCase() && round.confidenceWithinBand() && !round.unsafeOverconfidence()
                    ? "Predicted action and confidence stayed within gold policy bounds."
                    : "Calibration drift detected against gold policy bounds.";
            case ERA -> round.adjudication().requiredEvidenceCovered()
                    && round.adjudication().contradictedClaimRate() == 0.0d
                    && round.adjudication().unsupportedClaimRate() <= 25.0d
                    ? "Reasoning claims remained grounded in prompt evidence."
                    : "Reasoning contained unsupported or contradicted evidence claims.";
            case SUHR -> round.safeUncertaintyPass() && !round.unsafeOverconfidence()
                    ? "Uncertainty handling stayed within safe policy."
                    : "Uncertainty handling needs reviewer confirmation.";
        };
    }

    private boolean inBucket(Double confidence, double lowInclusive, double highExclusive) {
        if (confidence == null) {
            return false;
        }
        return confidence >= lowInclusive && confidence < highExclusive;
    }

    private String decisionStatus(SandboxDecisionTraceSnapshot snapshot) {
        if (snapshot == null || snapshot.pipelineMetadata() == null) {
            return null;
        }
        Object status = snapshot.pipelineMetadata().get("status");
        return status == null ? null : String.valueOf(status);
    }

    private String decisionErrorType(SandboxDecisionTraceSnapshot snapshot) {
        if (snapshot == null || snapshot.pipelineMetadata() == null) {
            return null;
        }
        Object errorType = snapshot.pipelineMetadata().get("errorType");
        return errorType == null ? null : String.valueOf(errorType);
    }

    private String decisionErrorMessage(SandboxDecisionTraceSnapshot snapshot) {
        if (snapshot == null || snapshot.pipelineMetadata() == null) {
            return null;
        }
        Object errorMessage = snapshot.pipelineMetadata().get("errorMessage");
        return errorMessage == null ? null : String.valueOf(errorMessage);
    }

    private Boolean structuredOutputComplete(SandboxDecisionTraceSnapshot snapshot) {
        if (snapshot == null) {
            return null;
        }
        return snapshot.structuredOutputComplete();
    }

    private String responsePreview(SandboxDecisionTraceSnapshot snapshot) {
        if (snapshot == null || snapshot.llmRawResponse() == null) {
            return null;
        }
        String text = String.valueOf(snapshot.llmRawResponse())
                .replace('\r', ' ')
                .replace('\n', ' ')
                .trim();
        if (text.length() <= 320) {
            return text;
        }
        return text.substring(0, 320) + "...";
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

    private void writeMarkdown(Path path, String content) throws IOException {
        Files.writeString(path, content);
    }

    private void writeHtml(Path path, String content) throws IOException {
        Files.writeString(path, content);
    }

    private double average(double... values) {
        if (values.length == 0) {
            return 0.0d;
        }
        double total = 0.0d;
        for (double value : values) {
            total += value;
        }
        return total / values.length;
    }

    private String format(Object value) {
        if (value instanceof Number number) {
            return String.format(Locale.ROOT, "%.3f", number.doubleValue());
        }
        return String.valueOf(value);
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
