package io.contexa.contexacore.verification.metric;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckResultView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class OfficialPromptQualityMetricContractGate {

    public static final String CONTRACT_VERSION = FinalPromptMetricContractCatalog.load(new ObjectMapper()).contractVersion();

    private static final Set<String> ALLOWED_STATES = Set.of(
            "success",
            "threshold_failed",
            "input_not_ready",
            "gate_failed",
            "insufficient",
            "not_applicable",
            "missing"
    );

    private final Set<String> expectedMetricCodes;

    public OfficialPromptQualityMetricContractGate(OfficialVerificationMetricCatalog metricCatalog) {
        OfficialVerificationMetricCatalog catalog = metricCatalog == null
                ? new OfficialVerificationMetricCatalog()
                : metricCatalog;
        this.expectedMetricCodes = catalog.promptQualityMetrics().stream()
                .map(metric -> normalize(metric.code()))
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    public Map<String, OfficialMetricEvaluationResult> validateEvaluationResults(
            Map<String, OfficialMetricEvaluationResult> rawResults
    ) {
        Map<String, OfficialMetricEvaluationResult> normalizedResults = normalizeResults(rawResults);
        List<String> violations = new ArrayList<>();
        validateMetricSet(normalizedResults.keySet(), violations);
        normalizedResults.forEach((metricCode, result) -> validateResult(metricCode, result, violations));
        throwIfViolations(violations);
        return Map.copyOf(normalizedResults);
    }

    public void validateRunViews(List<? extends OfficialVerificationRunView> runs) {
        List<String> violations = new ArrayList<>();
        Map<String, OfficialVerificationRunView> runsByMetric = new LinkedHashMap<>();
        if (runs != null) {
            for (OfficialVerificationRunView run : runs) {
                if (run == null) {
                    violations.add("official metric run view is null");
                    continue;
                }
                String metricCode = normalize(run.endpointKey());
                if (!hasText(metricCode)) {
                    violations.add("official metric run has blank metric code");
                    continue;
                }
                if (runsByMetric.putIfAbsent(metricCode, run) != null) {
                    violations.add("official metric run is duplicated: " + metricCode);
                }
            }
        }
        validateMetricSet(runsByMetric.keySet(), violations);
        runsByMetric.forEach((metricCode, run) -> validateRunView(metricCode, run, violations));
        throwIfViolations(violations);
    }

    public Set<String> expectedMetricCodes() {
        return Set.copyOf(expectedMetricCodes);
    }

    private Map<String, OfficialMetricEvaluationResult> normalizeResults(
            Map<String, OfficialMetricEvaluationResult> rawResults
    ) {
        if (rawResults == null || rawResults.isEmpty()) {
            return Map.of();
        }
        Map<String, OfficialMetricEvaluationResult> normalized = new LinkedHashMap<>();
        rawResults.forEach((key, value) -> normalized.put(normalize(key), value));
        return normalized;
    }

    private void validateMetricSet(Set<String> actualMetricCodes, List<String> violations) {
        Set<String> actual = actualMetricCodes == null
                ? Set.of()
                : actualMetricCodes.stream()
                .map(OfficialPromptQualityMetricContractGate::normalize)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (!actual.equals(expectedMetricCodes)) {
            Set<String> missing = new LinkedHashSet<>(expectedMetricCodes);
            missing.removeAll(actual);
            Set<String> unexpected = new LinkedHashSet<>(actual);
            unexpected.removeAll(expectedMetricCodes);
            if (!missing.isEmpty()) {
                violations.add("official prompt-quality metric set is missing: " + missing);
            }
            if (!unexpected.isEmpty()) {
                violations.add("official prompt-quality metric set has unexpected metrics: " + unexpected);
            }
        }
    }

    private void validateResult(
            String metricCode,
            OfficialMetricEvaluationResult result,
            List<String> violations
    ) {
        if (result == null) {
            violations.add("official metric result is null: " + metricCode);
            return;
        }
        if (!metricCode.equals(normalize(result.metricCode()))) {
            violations.add("official metric result code mismatch for " + metricCode + ": " + result.metricCode());
        }
        validateState(metricCode, result.state(), violations);
        List<OfficialMetricCheckObservation> checks = result.checks() == null
                ? List.of()
                : result.checks();
        List<OfficialMetricCheckObservation> evaluatedChecks = checks.stream()
                .filter(OfficialPromptQualityMetricContractGate::isEvaluatedCheck)
                .toList();
        validateCounts(metricCode, result.passedChecks(), result.totalChecks(), evaluatedChecks.size(),
                (int) evaluatedChecks.stream().filter(check -> check != null && check.passed()).count(), violations);
        if (checks.isEmpty()) {
            violations.add("official metric result has no checks: " + metricCode);
        }
        for (OfficialMetricCheckObservation check : checks) {
            validateCheck(metricCode, check, violations);
        }
    }

    private void validateRunView(String metricCode, OfficialVerificationRunView run, List<String> violations) {
        validateState(metricCode, run.state(), violations);
        List<? extends OfficialVerificationCheckResultView> checks = run.checks() == null ? List.of() : run.checks();
        List<? extends OfficialVerificationCheckResultView> evaluatedChecks = checks.stream()
                .filter(OfficialPromptQualityMetricContractGate::isEvaluatedCheck)
                .toList();
        validateCounts(metricCode, run.passedChecks(), run.totalChecks(), evaluatedChecks.size(),
                (int) evaluatedChecks.stream().filter(check -> check != null && check.pass()).count(), violations);
        if (checks.isEmpty()) {
            violations.add("official metric run has no checks: " + metricCode);
        }
        for (OfficialVerificationCheckResultView check : checks) {
            validateCheck(metricCode, check, violations);
        }
        if (run.rawEvidence() == null || !CONTRACT_VERSION.equals(String.valueOf(run.rawEvidence().get("metricContractVersion")))) {
            violations.add("official metric run does not carry contract version: " + metricCode);
        }
        if (run.analysisFacts() == null || !CONTRACT_VERSION.equals(run.analysisFacts().get("metricContractVersion"))) {
            violations.add("official metric analysis facts do not carry contract version: " + metricCode);
        }
    }

    private void validateCounts(
            String metricCode,
            int declaredPassed,
            int declaredTotal,
            int actualTotal,
            int actualPassed,
            List<String> violations
    ) {
        if (declaredTotal != actualTotal) {
            violations.add("official metric total check count mismatch for " + metricCode
                    + ": declared=" + declaredTotal + ", actual=" + actualTotal);
        }
        if (declaredPassed != actualPassed) {
            violations.add("official metric passed check count mismatch for " + metricCode
                    + ": declared=" + declaredPassed + ", actual=" + actualPassed);
        }
    }

    private void validateState(String metricCode, String state, List<String> violations) {
        String normalized = state == null ? "" : state.trim().toLowerCase(Locale.ROOT);
        if (!ALLOWED_STATES.contains(normalized)) {
            violations.add("official metric has unsupported state for " + metricCode + ": " + state);
        }
    }

    private void validateCheck(
            String metricCode,
            OfficialMetricCheckObservation check,
            List<String> violations
    ) {
        if (check == null) {
            violations.add("official metric check is null: " + metricCode);
            return;
        }
        validateCheckFields(metricCode, check.checkCode(), check.label(), check.expectedValue(), check.actualValue(),
                check.passed(), check.source(), check.severity(), check.failureType(), check.remediationOwner(),
                check.operatorReason(), check.nextAction(), check.reverifyCriterion(), violations);
    }

    private void validateCheck(
            String metricCode,
            OfficialVerificationCheckResultView check,
            List<String> violations
    ) {
        if (check == null) {
            violations.add("official metric check is null: " + metricCode);
            return;
        }
        validateCheckFields(metricCode, check.checkCode(), check.label(), check.expectedValue(), check.actualValue(),
                check.pass(), check.source(), check.severity(), check.failureType(), check.remediationOwner(),
                check.operatorReason(), check.nextAction(), check.reverifyCriterion(), violations);
    }

    private void validateCheckFields(
            String metricCode,
            String checkCode,
            String label,
            String expectedValue,
            String actualValue,
            boolean passed,
            String source,
            String severity,
            String failureType,
            String remediationOwner,
            String operatorReason,
            String nextAction,
            String reverifyCriterion,
            List<String> violations
    ) {
        String normalizedCheckCode = normalize(checkCode);
        if (!hasText(normalizedCheckCode) || "CHECK".equals(normalizedCheckCode)) {
            violations.add("official metric check has no stable check code: " + metricCode);
        }
        String requiredPrefix = metricCodePrefix(metricCode);
        if (hasText(normalizedCheckCode) && !normalizedCheckCode.startsWith(requiredPrefix + "_")) {
            violations.add("official metric check code does not belong to metric " + metricCode + ": " + checkCode);
        }
        if (!hasText(label)) {
            violations.add("official metric check label is blank: " + metricCode + "/" + checkCode);
        }
        validateOperatorText(metricCode, checkCode, "label", label, violations);
        if (!hasText(expectedValue)) {
            violations.add("official metric check expected value is blank: " + metricCode + "/" + checkCode);
        }
        validateOperatorText(metricCode, checkCode, "expected value", expectedValue, violations);
        if (!hasText(actualValue)) {
            violations.add("official metric check actual value is blank: " + metricCode + "/" + checkCode);
        }
        validateOperatorText(metricCode, checkCode, "actual value", actualValue, violations);
        if (!hasText(source)) {
            violations.add("official metric check evidence source is blank: " + metricCode + "/" + checkCode);
        }
        validateOperatorText(metricCode, checkCode, "operator reason", operatorReason, violations);
        validateOperatorText(metricCode, checkCode, "next action", nextAction, violations);
        validateOperatorText(metricCode, checkCode, "reverify criterion", reverifyCriterion, violations);
        if (!passed) {
            if (!hasText(severity)) {
                violations.add("failed official metric check has no severity: " + metricCode + "/" + checkCode);
            }
            if (!hasText(failureType)) {
                violations.add("failed official metric check has no failure type: " + metricCode + "/" + checkCode);
            }
            if (!hasText(remediationOwner)) {
                violations.add("failed official metric check has no remediation owner: " + metricCode + "/" + checkCode);
            }
            if (!hasText(operatorReason)) {
                violations.add("failed official metric check has no operator reason: " + metricCode + "/" + checkCode);
            }
            if (!hasText(nextAction)) {
                violations.add("failed official metric check has no next action: " + metricCode + "/" + checkCode);
            }
            if (!hasText(reverifyCriterion)) {
                violations.add("failed official metric check has no reverify criterion: " + metricCode + "/" + checkCode);
            }
        }
    }

    private void validateOperatorText(
            String metricCode,
            String checkCode,
            String field,
            String value,
            List<String> violations
    ) {
        if (!OfficialPromptQualityNarrativeCatalog.hasPlainOperatorText(value)) {
            violations.add("official metric check " + field
                    + " is not operator-readable Korean diagnostic text: " + metricCode + "/" + checkCode);
        }
    }

    private void throwIfViolations(List<String> violations) {
        if (violations == null || violations.isEmpty()) {
            return;
        }
        throw new OfficialPromptQualityMetricContractViolationException(
                "Official prompt-quality metric contract " + CONTRACT_VERSION + " was violated: "
                        + String.join("; ", violations));
    }

    private static String metricCodePrefix(String metricCode) {
        return normalize(metricCode);
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static boolean isEvaluatedCheck(OfficialMetricCheckObservation check) {
        return check != null
                && !"INTERNAL_REFERENCE".equalsIgnoreCase(check.readinessScope())
                && !isNotApplicable(check.purposeResult());
    }

    private static boolean isEvaluatedCheck(OfficialVerificationCheckResultView check) {
        return check != null
                && !"INTERNAL_REFERENCE".equalsIgnoreCase(check.readinessScope())
                && !isNotApplicable(check.purposeResult());
    }

    private static boolean isNotApplicable(String value) {
        return "NOT_APPLICABLE".equals(normalize(value));
    }
}
