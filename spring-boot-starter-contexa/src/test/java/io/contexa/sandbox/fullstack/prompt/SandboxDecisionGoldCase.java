package io.contexa.sandbox.fullstack.prompt;

import java.util.List;

public record SandboxDecisionGoldCase(
        String scenarioKey,
        String roundKey,
        String scenarioFamily,
        String behaviorPhase,
        String anomalySignal,
        List<String> safeActions,
        List<String> unsafeActions,
        SandboxDecisionConfidenceBand confidenceBand,
        boolean uncertaintyRequired,
        List<String> requiredEvidenceTokens,
        List<String> forbiddenReasoningTokens,
        String goldVersion) {

    public SandboxDecisionGoldCase {
        safeActions = safeActions == null ? List.of() : List.copyOf(safeActions);
        unsafeActions = unsafeActions == null ? List.of() : List.copyOf(unsafeActions);
        requiredEvidenceTokens = requiredEvidenceTokens == null ? List.of() : List.copyOf(requiredEvidenceTokens);
        forbiddenReasoningTokens = forbiddenReasoningTokens == null ? List.of() : List.copyOf(forbiddenReasoningTokens);
    }

    public boolean allows(String action) {
        if (action == null || action.isBlank()) {
            return false;
        }
        return safeActions.stream().anyMatch(candidate -> candidate.equalsIgnoreCase(action.trim()));
    }

    public boolean forbids(String action) {
        if (action == null || action.isBlank()) {
            return false;
        }
        return unsafeActions.stream().anyMatch(candidate -> candidate.equalsIgnoreCase(action.trim()));
    }
}
