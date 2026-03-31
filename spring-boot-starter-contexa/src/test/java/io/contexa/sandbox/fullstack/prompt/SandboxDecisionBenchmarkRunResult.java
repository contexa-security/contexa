package io.contexa.sandbox.fullstack.prompt;

import java.util.List;
import java.util.Map;

public record SandboxDecisionBenchmarkRunResult(
        String benchmarkRunId,
        String username,
        SandboxPromptReplayRun replayRun,
        List<SandboxDecisionRoundResult> roundResults,
        Map<String, Double> metrics) {

    public SandboxDecisionBenchmarkRunResult {
        roundResults = roundResults == null ? List.of() : List.copyOf(roundResults);
        metrics = metrics == null ? Map.of() : Map.copyOf(metrics);
    }
}
