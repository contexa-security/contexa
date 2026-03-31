package io.contexa.sandbox.fullstack.prompt;

public record SandboxDecisionRoundResult(
        String benchmarkRunId,
        String username,
        String scenarioKey,
        String scenarioFamily,
        int roundNumber,
        String roundKey,
        String predictedAction,
        Double predictedConfidence,
        String predictedReasoning,
        SandboxDecisionGoldCase goldCase,
        SandboxDecisionAdjudication adjudication,
        boolean actionAllowedByGoldCase,
        boolean confidenceWithinBand,
        boolean unsafeOverconfidence,
        boolean safeUncertaintyPass,
        double cdcScore,
        double eraScore,
        double suhrScore,
        SandboxPromptReplayRound replayRound) {
}
