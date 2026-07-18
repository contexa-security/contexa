package io.contexa.contexacore.verification.runtime.prompt;

import java.util.List;
import org.springframework.util.StringUtils;

final class FinalPromptMetricResultAssembler {

    private FinalPromptMetricResultAssembler() {
    }

    static FinalPromptMetricResult result(String metricCode, List<FinalPromptMetricCheck> checks) {
        List<FinalPromptMetricCheck> safeChecks = copyChecks(metricCode, checks);
        List<FinalPromptMetricCheck> evaluatedChecks = safeChecks.stream()
                .filter(check -> !"INTERNAL_REFERENCE".equalsIgnoreCase(readinessScope(check)))
                .filter(check -> !"NOT_APPLICABLE".equalsIgnoreCase(
                        FinalPromptDisplayValues.firstNonBlank(check.purposeResult(), "")))
                .toList();
        int total = evaluatedChecks.size();
        int passed = (int) evaluatedChecks.stream().filter(FinalPromptMetricCheck::passed).count();
        double score = total == 0 ? 100.0d : (passed * 100.0d) / total;
        String state = resultState(safeChecks, evaluatedChecks, passed, total);
        return new FinalPromptMetricResult(metricCode, score, passed, total, state, safeChecks);
    }

    private static String resultState(
            List<FinalPromptMetricCheck> allChecks,
            List<FinalPromptMetricCheck> checks,
            int passed,
            int total) {
        boolean inputNotReady = allChecks.stream()
                .anyMatch(check -> !check.passed()
                        && ("INPUT_NOT_READY".equalsIgnoreCase(check.inputReadinessState())
                        || "INPUT_NOT_READY".equalsIgnoreCase(check.purposeResult())));
        if (inputNotReady) {
            return "input_not_ready";
        }
        if (total == 0) {
            return "not_applicable";
        }
        if (passed == total) {
            return "success";
        }
        boolean customerPromptPurposeFailed = checks.stream()
                .anyMatch(check -> !check.passed()
                        && check.customerVisible()
                        && "CUSTOMER_PROMPT_QUALITY".equalsIgnoreCase(readinessScope(check))
                        && !"INPUT_NOT_READY".equalsIgnoreCase(check.inputReadinessState())
                        && !"INPUT_NOT_READY".equalsIgnoreCase(check.purposeResult()));
        return customerPromptPurposeFailed ? "threshold_failed" : "gate_failed";
    }

    private static List<FinalPromptMetricCheck> copyChecks(
            String metricCode,
            List<FinalPromptMetricCheck> checks) {
        if (checks == null) {
            return List.of();
        }
        for (int index = 0; index < checks.size(); index++) {
            if (checks.get(index) == null) {
                throw new IllegalStateException(
                        "Final prompt metric evaluator produced a null check. metricCode="
                                + metricCode + ", checkIndex=" + index);
            }
        }
        return List.copyOf(checks);
    }

    private static String readinessScope(FinalPromptMetricCheck check) {
        String scope = check == null ? "" : check.readinessScope();
        return StringUtils.hasText(scope)
                ? scope.trim()
                : "INTERNAL_EXECUTION_GATE";
    }
}