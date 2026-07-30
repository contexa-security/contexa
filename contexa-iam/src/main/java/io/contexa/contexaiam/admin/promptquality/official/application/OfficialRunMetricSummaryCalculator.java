package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialMetricPurposeEvidence;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunCheckDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunSummaryCounts;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import org.springframework.util.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

final class OfficialRunMetricSummaryCalculator {

    int detailTotalChecks(List<OfficialRunCheckDetail> checks, int fallback) {
        return checks != null && !checks.isEmpty()
                ? evaluatedDetailChecks(checks).size()
                : Math.max(fallback, 0);
    }

    int detailPassedChecks(List<OfficialRunCheckDetail> checks, int fallback) {
        if (checks != null && !checks.isEmpty()) {
            return (int) evaluatedDetailChecks(checks).stream().filter(OfficialRunCheckDetail::pass).count();
        }
        return Math.max(fallback, 0);
    }

    private List<OfficialRunCheckDetail> evaluatedDetailChecks(List<OfficialRunCheckDetail> checks) {
        return checks.stream()
                .filter(Objects::nonNull)
                .filter(check -> !"INTERNAL_REFERENCE".equals(normalize(check.readinessScope()))
                        || "NOT_APPLICABLE".equals(normalize(check.purposeResult())))
                .toList();
    }

    List<OfficialActualPromptProblem> actualPromptProblems(OperatorSnapshot snapshot) {
        return snapshot == null || !snapshot.available() ? List.of() : snapshot.actualPromptProblems();
    }

    List<String> actualPromptProblemSummaries(List<OfficialActualPromptProblem> problems) {
        if (problems == null || problems.isEmpty()) {
            return List.of();
        }
        return problems.stream()
                .filter(problem -> problem != null && "BLOCKING".equalsIgnoreCase(valueOrEmpty(problem.severity())))
                .map(problem -> firstNonBlank(problem.promptLabel(), problem.fieldKey(), "final userPrompt issue")
                        + ": " + firstNonBlank(problem.whyItMatters(), problem.actualState(), problem.problemType(), "review required"))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    List<OperatorMetricSnapshot> safeOperatorMetrics(OperatorSnapshot snapshot) {
        if (snapshot == null || !snapshot.available() || snapshot.metrics() == null) {
            return List.of();
        }
        return snapshot.metrics();
    }

    List<OfficialActualPromptProblem> actualPromptProblemsForMetric(OperatorSnapshot snapshot, String metricCode) {
        return actualPromptProblemsForMetric(actualPromptProblems(snapshot), metricCode);
    }

    List<OfficialActualPromptProblem> actualPromptProblemsForMetric(
            List<OfficialActualPromptProblem> problems,
            String metricCode) {
        String normalizedMetric = normalize(metricCode);
        if (!StringUtils.hasText(normalizedMetric) || problems == null || problems.isEmpty()) {
            return List.of();
        }
        return problems.stream()
                .filter(Objects::nonNull)
                .filter(problem -> problem.metricCodes().stream().anyMatch(code -> same(code, normalizedMetric)))
                .toList();
    }

    OfficialRunSummaryCounts summaryCounts(
            List<OfficialVerificationMetricTrace> runs,
            List<OfficialActualPromptProblem> actualPromptProblems) {
        List<OfficialVerificationMetricTrace> safeRuns = runs == null
                ? List.of()
                : runs.stream().filter(Objects::nonNull).toList();
        List<OfficialActualPromptProblem> safeProblems = actualPromptProblems == null
                ? List.of()
                : actualPromptProblems.stream().filter(Objects::nonNull).toList();
        Set<String> blockedMetricCodes = safeProblems.stream()
                .flatMap(problem -> problem.metricCodes().stream())
                .map(this::normalize)
                .filter(StringUtils::hasText)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        SummaryAccumulator totals = new SummaryAccumulator();
        for (OfficialVerificationMetricTrace run : safeRuns) {
            int actualProblemCount = actualPromptProblemsForMetric(safeProblems, run.metricCode()).size();
            totals.add(metricSummarySplit(run, actualProblemCount));
        }
        return totals.toCounts(safeProblems.size(), blockedMetricCodes.size());
    }

    String nextActionHref(String packageId, String aggregateRunId, OfficialRunSummaryCounts counts) {
        if (!StringUtils.hasText(packageId) || counts == null) {
            return null;
        }
        boolean reviewRequired = counts.actualProblems() > 0
                || counts.inputReviewMetrics() > 0
                || counts.inputReadinessChecks() > 0
                || counts.gateConditions() > 0
                || counts.gateMetrics() > 0;
        if (!reviewRequired) {
            return null;
        }
        StringBuilder href = new StringBuilder("/contexa/admin/prompt-quality/verification/metrics")
                .append("?packageId=")
                .append(urlEncode(packageId));
        if (StringUtils.hasText(aggregateRunId)) {
            href.append("&aggregateRunId=").append(urlEncode(aggregateRunId));
        }
        return href.toString();
    }

    List<OfficialRunCheckDetail> evaluatedChecks(OfficialVerificationMetricTrace run) {
        if (run == null || run.checks() == null || run.checks().isEmpty()) {
            return List.of();
        }
        return run.checks().stream()
                .filter(Objects::nonNull)
                .filter(check -> !isNotApplicableCheck(run, check))
                .filter(check -> purposeEvidenceForCheck(run, check).stream()
                        .noneMatch(evidence -> "INTERNAL_REFERENCE".equals(normalize(evidence.readinessScope()))))
                .toList();
    }

    private MetricSummarySplit metricSummarySplit(OfficialVerificationMetricTrace run, int actualProblemCount) {
        if (run == null || (metricNotApplicable(run) && actualProblemCount == 0)) {
            return MetricSummarySplit.empty();
        }
        List<OfficialRunCheckDetail> checks = evaluatedChecks(run);
        int technicalTotal = checks.isEmpty() ? Math.max(run.totalChecks(), 0) : checks.size();
        int technicalPassed = checks.isEmpty()
                ? Math.max(run.passedChecks(), 0)
                : (int) checks.stream().filter(OfficialRunCheckDetail::pass).count();
        int failed = Math.max(technicalTotal - technicalPassed, 0);
        int inputFailed = 0;
        int gateFailed = 0;
        int otherFailed = 0;
        int countedFailed = 0;
        for (OfficialRunCheckDetail check : checks) {
            if (check.pass()) {
                continue;
            }
            countedFailed++;
            List<OfficialMetricPurposeEvidence> evidence = purposeEvidenceForCheck(run, check);
            if (hasScope(evidence, "CUSTOMER_PROMPT_QUALITY", true)) {
                continue;
            }
            if (hasScope(evidence, "INPUT_READINESS", false)) {
                inputFailed++;
            } else if (hasScope(evidence, "INTERNAL_EXECUTION_GATE", false)) {
                gateFailed++;
            } else {
                otherFailed++;
            }
        }
        otherFailed += Math.max(failed - countedFailed, 0);
        return new MetricSummarySplit(technicalTotal, technicalPassed, failed, inputFailed, gateFailed, otherFailed);
    }

    private boolean metricNotApplicable(OfficialVerificationMetricTrace run) {
        String state = normalize(run.state());
        if ("NOT_APPLICABLE".equals(state) || "NOT_APPLICABLE_METRIC".equals(state)) {
            return true;
        }
        List<OfficialRunCheckDetail> checks = run.checks() == null ? List.of() : run.checks();
        return !checks.isEmpty()
                && checks.stream().filter(Objects::nonNull).anyMatch(check -> isNotApplicableCheck(run, check))
                && evaluatedChecks(run).isEmpty();
    }

    private boolean isNotApplicableCheck(OfficialVerificationMetricTrace run, OfficialRunCheckDetail check) {
        List<OfficialMetricPurposeEvidence> evidence = purposeEvidenceForCheck(run, check);
        return !evidence.isEmpty() && evidence.stream()
                .allMatch(item -> "NOT_APPLICABLE".equals(normalize(item.purposeResult()))
                        || "NOT_APPLICABLE".equals(normalize(item.readinessScope())));
    }

    private List<OfficialMetricPurposeEvidence> purposeEvidenceForCheck(
            OfficialVerificationMetricTrace run,
            OfficialRunCheckDetail check) {
        String metricCode = normalize(run == null ? null : run.metricCode());
        String checkCode = normalize(check == null ? null : check.checkCode());
        if (run == null || run.purposeEvidence() == null || run.purposeEvidence().isEmpty()) {
            return List.of();
        }
        return run.purposeEvidence().stream()
                .filter(Objects::nonNull)
                .filter(evidence -> (!StringUtils.hasText(metricCode) || same(evidence.metricCode(), metricCode))
                        && (!StringUtils.hasText(checkCode)
                        || metricCheckCodesMatch(metricCode, checkCode, evidence.checkCode())))
                .toList();
    }

    private boolean hasScope(List<OfficialMetricPurposeEvidence> evidence, String scope, boolean customerVisibleRequired) {
        String normalizedScope = normalize(scope);
        return evidence != null && evidence.stream()
                .filter(Objects::nonNull)
                .anyMatch(item -> (!customerVisibleRequired || item.customerVisible())
                        && normalizedScope.equals(normalize(item.readinessScope())));
    }

    private boolean metricCheckCodesMatch(String metricCode, String runCheckCode, String evidenceCheckCode) {
        String runCode = normalize(runCheckCode);
        String evidenceCode = normalize(evidenceCheckCode);
        if (!StringUtils.hasText(runCode) || !StringUtils.hasText(evidenceCode)) {
            return false;
        }
        if (runCode.equals(evidenceCode)) {
            return true;
        }
        String metric = normalize(metricCode);
        return StringUtils.hasText(metric)
                && stripMetricPrefix(metric, runCode).equals(stripMetricPrefix(metric, evidenceCode));
    }

    private String stripMetricPrefix(String metricCode, String checkCode) {
        String metric = normalize(metricCode);
        String code = normalize(checkCode);
        String prefix = metric + "_";
        return StringUtils.hasText(metric) && code.startsWith(prefix) ? code.substring(prefix.length()) : code;
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private boolean same(String left, String right) {
        return StringUtils.hasText(left) && StringUtils.hasText(right) && left.trim().equalsIgnoreCase(right.trim());
    }

    private String valueOrEmpty(String value) {
        return StringUtils.hasText(value) ? value.trim() : "";
    }

    private String firstNonBlank(String... values) {
        if (values != null) {
            for (String value : values) {
                if (StringUtils.hasText(value)) {
                    return value.trim();
                }
            }
        }
        return "";
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private record MetricSummarySplit(
            int technicalTotal,
            int technicalPassed,
            int criteriaFailed,
            int inputFailed,
            int gateFailed,
            int otherFailed) {
        static MetricSummarySplit empty() {
            return new MetricSummarySplit(0, 0, 0, 0, 0, 0);
        }
    }

    private static final class SummaryAccumulator {
        private int technicalTotal;
        private int technicalPassed;
        private int criteriaFailed;
        private int gateConditions;
        private int inputReviewMetrics;
        private int inputReadinessChecks;
        private int gateMetrics;
        private int otherFailed;
        private int technicalFailed;

        void add(MetricSummarySplit split) {
            technicalTotal += split.technicalTotal();
            technicalPassed += split.technicalPassed();
            criteriaFailed += split.criteriaFailed();
            if (split.gateFailed() > 0) {
                gateConditions += split.gateFailed();
                gateMetrics++;
            }
            if (split.inputFailed() > 0) {
                inputReviewMetrics++;
                inputReadinessChecks += split.inputFailed();
            }
            otherFailed += split.otherFailed();
            technicalFailed += split.gateFailed() + split.otherFailed();
        }

        OfficialRunSummaryCounts toCounts(int actualProblems, int blockedMetricCount) {
            return new OfficialRunSummaryCounts(
                    actualProblems, blockedMetricCount, technicalTotal, technicalPassed, technicalFailed,
                    gateConditions, inputReviewMetrics, inputReadinessChecks, criteriaFailed, gateMetrics, otherFailed);
        }
    }
}