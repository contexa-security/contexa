package io.contexa.contexacore.verification.contract.prompt;

import java.util.List;

/**
 * Shared official verification replay scenario contract for a single authenticated user profile.
 */
public record OfficialVerificationPromptContractScenario(
        String scenarioKey,
        String experimentGroup,
        String scenarioHeader,
        String expectedActionHeader,
        String userProfileKey,
        String scenarioFamily,
        List<OfficialVerificationPromptContractRoundPlan> roundPlans) {

    public OfficialVerificationPromptContractScenario {
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
            throw new IllegalArgumentException("OfficialVerificationPromptContractScenario requires at least 3 round plans");
        }
        roundPlans = List.copyOf(roundPlans);
    }

    public int roundCount() {
        return roundPlans.size();
    }

    public OfficialVerificationPromptContractRoundPlan roundPlanForRound(int oneBasedRound) {
        int index = oneBasedRound - 1;
        if (index < 0 || index >= roundPlans.size()) {
            throw new IllegalArgumentException("Round index out of bounds: " + oneBasedRound);
        }
        return roundPlans.get(index);
    }
}