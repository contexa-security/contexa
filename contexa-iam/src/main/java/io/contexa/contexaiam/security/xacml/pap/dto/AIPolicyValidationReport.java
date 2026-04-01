package io.contexa.contexaiam.security.xacml.pap.dto;

import java.util.List;

public record AIPolicyValidationReport(
        List<ValidationItem> items,
        boolean canApprove,
        String blockedReason) {

    public record ValidationItem(
            String checkName,
            CheckResult result,
            String detail) {
    }

    public enum CheckResult {
        PASS,
        WARNING,
        FAIL
    }

    public boolean hasFails() {
        return items.stream().anyMatch(i -> i.result() == CheckResult.FAIL);
    }

    public boolean hasWarnings() {
        return items.stream().anyMatch(i -> i.result() == CheckResult.WARNING);
    }
}
