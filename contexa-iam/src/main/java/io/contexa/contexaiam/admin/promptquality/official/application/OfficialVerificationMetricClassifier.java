package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckResultView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import org.springframework.util.StringUtils;

import java.util.Locale;
import java.util.Set;

final class OfficialVerificationMetricClassifier {

    private static final Set<String> PASS_STATES = Set.of(
            "SUCCESS", "PASS", "PASSED", "VERIFIED", "COMPLETED");

    private OfficialVerificationMetricClassifier() {
    }

    static boolean runPassed(OfficialVerificationRunView run) {
        return run != null && passedState(run.state());
    }

    static boolean metricPassed(RuntimeEvidenceMetricResult metric) {
        return metric != null && passedState(metric.state());
    }

    static boolean metricNotApplicable(RuntimeEvidenceMetricResult metric) {
        if (metric == null) {
            return false;
        }
        String state = normalized(metric.state());
        return "NOT_APPLICABLE".equals(state) || "NOT APPLICABLE".equals(state);
    }

    static boolean snapshotMetricPassed(RuntimeEvidenceMetricResult metric) {
        return metric != null && PASS_STATES.contains(snapshotState(metric));
    }

    static boolean snapshotMetricFailed(RuntimeEvidenceMetricResult metric) {
        return metric != null && !snapshotMetricPassed(metric);
    }

    static String snapshotState(RuntimeEvidenceMetricResult metric) {
        return metric == null || metric.state() == null
                ? "" : metric.state().trim().toUpperCase(Locale.ROOT);
    }

    static int snapshotFailedCheckCount(RuntimeEvidenceMetricResult metric) {
        if ("NOT_APPLICABLE".equals(snapshotState(metric)) || snapshotMetricPassed(metric)) {
            return 0;
        }
        if (metric == null || metric.checks() == null) {
            return Math.max(metric == null ? 0 : metric.totalChecks() - metric.passedChecks(), 0);
        }
        return (int) metric.checks().stream()
                .filter(check -> evaluatedSnapshotCheck(check) && !check.pass())
                .count();
    }

    static int snapshotTotalCheckCount(RuntimeEvidenceMetricResult metric) {
        if (metric == null || "NOT_APPLICABLE".equals(snapshotState(metric))) {
            return 0;
        }
        if (metric.checks() != null && !metric.checks().isEmpty()) {
            return (int) metric.checks().stream().filter(OfficialVerificationMetricClassifier::evaluatedSnapshotCheck).count();
        }
        return Math.max(metric.totalChecks(), 0);
    }

    static int snapshotPassedCheckCount(RuntimeEvidenceMetricResult metric) {
        if (metric == null || "NOT_APPLICABLE".equals(snapshotState(metric))) {
            return 0;
        }
        if (snapshotMetricPassed(metric)) {
            return snapshotTotalCheckCount(metric);
        }
        if (metric.checks() != null && !metric.checks().isEmpty()) {
            return (int) metric.checks().stream()
                    .filter(check -> evaluatedSnapshotCheck(check) && check.pass())
                    .count();
        }
        return Math.max(metric.passedChecks(), 0);
    }

    static boolean snapshotNotApplicableCheck(RuntimeEvidenceCheckResult check) {
        return check != null && "NOT_APPLICABLE".equalsIgnoreCase(check.purposeResult());
    }

    static boolean evaluatedSnapshotCheck(RuntimeEvidenceCheckResult check) {
        return check != null
                && !snapshotNotApplicableCheck(check)
                && !"INTERNAL_REFERENCE".equalsIgnoreCase(check.readinessScope());
    }
    static boolean customerBlocking(RuntimeEvidenceMetricResult metric) {
        if (metric == null || internalGateMetric(metric.metricCode())) {
            return false;
        }
        if (metric.checks() == null || metric.checks().isEmpty()) {
            return !metricPassed(metric);
        }
        return metric.checks().stream()
                .anyMatch(check -> customerPromptQualityCheck(check)
                        && !check.pass()
                        && !runtimeInputNotReady(check)
                        && "BLOCKING".equalsIgnoreCase(firstNonBlank(check.severity(), "")));
    }

    static boolean runtimeInputNotReady(RuntimeEvidenceCheckResult check) {
        if (check == null) {
            return false;
        }
        String readiness = normalized(check.inputReadinessState());
        String purpose = normalized(check.purposeResult());
        String failure = normalized(check.failureType());
        return "NOT_READY".equals(readiness)
                || "INPUT_NOT_READY".equals(readiness)
                || "NOT_EVALUATED_INPUT_NOT_READY".equals(purpose)
                || "INPUT_NOT_READY".equals(purpose)
                || "INPUT_NOT_READY".equals(failure);
    }

    static boolean finalPromptInputNotReady(OfficialVerificationCheckResultView check) {
        if (check == null) {
            return false;
        }
        String readiness = normalized(check.inputReadinessState());
        String purpose = normalized(check.purposeResult());
        String failure = normalized(check.failureType());
        if ("NOT_READY".equals(readiness)
                || "INPUT_NOT_READY".equals(readiness)
                || "NOT_EVALUATED_INPUT_NOT_READY".equals(purpose)
                || "INPUT_NOT_READY".equals(purpose)) {
            return true;
        }
        if (!"INPUT_NOT_READY".equals(failure)) {
            return false;
        }
        String details = normalizedLower(check.actualValue()) + " " + normalizedLower(check.operatorReason());
        return details.contains("missing:")
                || details.contains("missing inputs")
                || details.contains("값 없음")
                || details.contains("누락");
    }

    static boolean customerPromptQualityCheck(RuntimeEvidenceCheckResult check) {
        return check != null
                && check.customerVisible()
                && "CUSTOMER_PROMPT_QUALITY".equalsIgnoreCase(firstNonBlank(
                        check.readinessScope(), "CUSTOMER_PROMPT_QUALITY"));
    }

    static boolean customerPromptQualityCheck(OfficialVerificationCheckResultView check) {
        return check != null
                && check.customerVisible()
                && "CUSTOMER_PROMPT_QUALITY".equalsIgnoreCase(firstNonBlank(
                        check.readinessScope(), "CUSTOMER_PROMPT_QUALITY"));
    }

    static String readinessScope(OfficialVerificationCheckResultView check) {
        if (check == null) {
            return "CUSTOMER_PROMPT_QUALITY";
        }
        return firstNonBlank(
                check.readinessScope(),
                check.customerVisible() ? "CUSTOMER_PROMPT_QUALITY" : "INTERNAL_EXECUTION_GATE");
    }

    static boolean officialFinalPromptCheck(OfficialVerificationCheckResultView check) {
        if (check == null || !StringUtils.hasText(check.source())) {
            return false;
        }
        String source = check.source().trim();
        String scope = normalized(check.readinessScope());
        return source.startsWith("finalUserPrompt.")
                || source.startsWith("finalSystemPrompt.")
                || source.startsWith("internalGate.")
                || "LLM_DECISION_QUALITY".equals(scope)
                || scope.startsWith("LLM_DECISION_");
    }

    static boolean blockingPromptComparison(OfficialVerificationPromptComparison comparison) {
        if (comparison == null) {
            return false;
        }
        String state = normalized(comparison.state());
        if (state.startsWith("FINAL_PROMPT_")) {
            return true;
        }
        return switch (state) {
            case "PROMPT_MISSING",
                    "FACT_MISSING",
                    "VALUE_MISMATCH",
                    "CONTRACT_MISMATCH",
                    "REQUIRED_MISSING",
                    "CONDITIONAL_REQUIRED_MISSING",
                    "UNKNOWN_WITHOUT_REASON",
                    "PROMPT_COMPACTED_SIGNAL",
                    "PRODUCER_NOT_AVAILABLE",
                    "PROVISIONAL_EVIDENCE",
                    "NO_DIRECT_COMPARABLE",
                    "BASELINE_MISMATCH_SIGNAL" -> true;
            default -> false;
        };
    }
    static boolean internalGateMetric(String metricCode) {
        return switch (normalized(metricCode)) {
            case "MTR", "RPI", "PRE" -> true;
            default -> false;
        };
    }

    private static boolean passedState(String state) {
        String normalized = normalized(state);
        return PASS_STATES.contains(normalized) || normalized.contains("THRESHOLD PASSED");
    }

    private static String normalized(String value) {
        return StringUtils.hasText(value) ? value.trim().toUpperCase(Locale.ROOT) : "";
    }

    private static String normalizedLower(String value) {
        return StringUtils.hasText(value) ? value.trim().toLowerCase(Locale.ROOT) : "";
    }

    private static String firstNonBlank(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }
}