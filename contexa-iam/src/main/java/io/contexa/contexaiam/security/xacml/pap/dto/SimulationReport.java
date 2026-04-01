package io.contexa.contexaiam.security.xacml.pap.dto;

import java.util.List;

public record SimulationReport(
        List<SimulationResult> results,
        SimulationSummary summary) {

    public record SimulationResult(
            SimulationTestCase testCase,
            String username,
            DecisionDetail currentResult,
            DecisionDetail newResult,
            boolean changed,
            String changeType) {
    }

    public record DecisionDetail(
            String decision,
            Long matchedPolicyId,
            String matchedPolicyName,
            String matchedExpression,
            List<String> userAuthorities) {
    }

    public record SimulationSummary(
            int unchanged,
            int allowToDeny,
            int denyToAllow,
            int otherChanges) {
    }
}
