package io.contexa.demo.comparison.support;

import java.util.Set;

public abstract class AbstractRunFailureSupport {

    private static final Set<String> PUBLIC_REASONS = Set.of(
            "WORKSPACE_EXPIRED", "INITIAL_CONDITIONS_NOT_MATCHED", "EXECUTION_FOUNDATION_UNAVAILABLE",
            "UNSUPPORTED_REQUEST_PLAN", "COMMAND_INPUT_CHANGED", "PREPARATION_ATTEMPT_LIMIT");

    protected String publicReason(String reason) {
        return reason != null && PUBLIC_REASONS.contains(reason) ? reason : "REQUEST_UNAVAILABLE";
    }
}
