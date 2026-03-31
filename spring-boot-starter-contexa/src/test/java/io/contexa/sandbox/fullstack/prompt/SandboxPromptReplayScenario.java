package io.contexa.sandbox.fullstack.prompt;

import java.util.List;

/**
 * Full-stack replay scenario for a single authenticated user.
 *
 * The scenario is not a static list of paths anymore.
 * It is a sequence of concrete round plans so benchmark "when" conditions
 * can model long-running normal behavior and subtle anomalies on the same account.
 */
public record SandboxPromptReplayScenario(
        String scenarioKey,
        String experimentGroup,
        String scenarioHeader,
        String expectedActionHeader,
        String userProfileKey,
        String scenarioFamily,
        List<SandboxPromptRoundPlan> roundPlans) {

    public SandboxPromptReplayScenario {
        if (scenarioKey == null || scenarioKey.isBlank()) {
            throw new IllegalArgumentException("scenarioKey must not be blank");
        }
        if (experimentGroup == null || experimentGroup.isBlank()) {
            throw new IllegalArgumentException("experimentGroup must not be blank");
        }
        if (scenarioHeader == null || scenarioHeader.isBlank()) {
            throw new IllegalArgumentException("scenarioHeader must not be blank");
        }
        if (expectedActionHeader == null || expectedActionHeader.isBlank()) {
            throw new IllegalArgumentException("expectedActionHeader must not be blank");
        }
        if (userProfileKey == null || userProfileKey.isBlank()) {
            throw new IllegalArgumentException("userProfileKey must not be blank");
        }
        if (scenarioFamily == null || scenarioFamily.isBlank()) {
            throw new IllegalArgumentException("scenarioFamily must not be blank");
        }
        if (roundPlans == null || roundPlans.size() < 3) {
            throw new IllegalArgumentException("SandboxPromptReplayScenario requires at least 3 round plans");
        }
        roundPlans = List.copyOf(roundPlans);
    }

    public int roundCount() {
        return roundPlans.size();
    }

    public SandboxPromptRoundPlan roundPlanForRound(int oneBasedRound) {
        int index = oneBasedRound - 1;
        if (index < 0 || index >= roundPlans.size()) {
            throw new IllegalArgumentException("Round index out of bounds: " + oneBasedRound);
        }
        return roundPlans.get(index);
    }

    public String requestPathForRound(int oneBasedRound) {
        return roundPlanForRound(oneBasedRound).requestPath();
    }

    public String clientIpForRound(int oneBasedRound) {
        return roundPlanForRound(oneBasedRound).clientIp();
    }

    public String browserUserAgentForRound(int oneBasedRound) {
        return roundPlanForRound(oneBasedRound).browserUserAgent();
    }

    public String simulatedUserAgentLabelForRound(int oneBasedRound) {
        return roundPlanForRound(oneBasedRound).simulatedUserAgentLabel();
    }

    public String deviceAliasForRound(int oneBasedRound) {
        return roundPlanForRound(oneBasedRound).deviceAlias();
    }

    public long cooldownBeforeRoundMsForRound(int oneBasedRound) {
        return roundPlanForRound(oneBasedRound).cooldownBeforeRoundMs();
    }

    /**
     * Compatibility helpers for code paths that still need a scenario-level default.
     * They always resolve to round 1, which acts as the initial login/device context.
     */
    public String clientIp() {
        return clientIpForRound(1);
    }

    public String browserUserAgent() {
        return browserUserAgentForRound(1);
    }

    public String simulatedUserAgentLabel() {
        return simulatedUserAgentLabelForRound(1);
    }
}
