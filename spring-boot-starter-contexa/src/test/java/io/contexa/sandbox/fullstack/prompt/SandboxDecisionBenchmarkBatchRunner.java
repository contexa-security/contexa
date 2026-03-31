package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class SandboxDecisionBenchmarkBatchRunner {

    private final SandboxFullStackPromptReplayHarness replayHarness;
    private final ObjectMapper objectMapper;
    private final SandboxPromptTruthRealLlmDecisionReplayExecutor realLlmDecisionReplayExecutor;

    public SandboxDecisionBenchmarkBatchRunner(
            SandboxFullStackPromptReplayHarness replayHarness,
            ObjectMapper objectMapper) {
        this(replayHarness, objectMapper, null);
    }

    public SandboxDecisionBenchmarkBatchRunner(
            SandboxFullStackPromptReplayHarness replayHarness,
            ObjectMapper objectMapper,
            SandboxPromptTruthRealLlmDecisionReplayExecutor realLlmDecisionReplayExecutor) {
        this.replayHarness = replayHarness;
        this.objectMapper = objectMapper;
        this.realLlmDecisionReplayExecutor = realLlmDecisionReplayExecutor;
    }

    public List<SandboxDecisionBenchmarkRunResult> execute(
            List<SandboxPromptReplayScenario> scenarios,
            int sampleCount,
            int roundCount,
            String password) {
        if (sampleCount <= 0) {
            throw new IllegalArgumentException("sampleCount must be positive");
        }
        if (roundCount < 3) {
            throw new IllegalArgumentException("roundCount must be at least 3");
        }
        if (scenarios == null || scenarios.isEmpty()) {
            throw new IllegalArgumentException("scenarios must not be empty");
        }

        List<SandboxDecisionBenchmarkRunResult> runResults = new ArrayList<>(sampleCount * scenarios.size());
        for (SandboxPromptReplayScenario scenario : scenarios) {
            for (int sampleIndex = 1; sampleIndex <= sampleCount; sampleIndex++) {
                String benchmarkRunId = scenario.scenarioKey().toLowerCase(Locale.ROOT)
                        + "-decision-run-" + sampleIndex;
                String username = String.format(
                        Locale.ROOT,
                        "decision-admin-%s-%03d@example.com",
                        scenario.scenarioKey().toLowerCase(Locale.ROOT).replace("_", "-"),
                        sampleIndex);

                SandboxPromptReplayRun replayRun = harvestPromptTruth(
                        username,
                        password,
                        benchmarkRunId,
                        SandboxPromptReplayScenarioCatalog.resizeScenario(scenario, roundCount));
                SandboxPromptReplayRun evaluatedReplayRun = replayRun;
                if (SandboxDecisionBenchmarkSettings.useRealLlm()) {
                    if (realLlmDecisionReplayExecutor == null) {
                        throw new IllegalStateException("Real LLM decision replay executor is required when sandbox.decision.real-llm=true");
                    }
                    evaluatedReplayRun = realLlmDecisionReplayExecutor.replayDecisions(replayRun);
                }
                runResults.add(SandboxDecisionMetricExtractor.evaluateRun(objectMapper, evaluatedReplayRun));
            }
        }
        return List.copyOf(runResults);
    }

    private SandboxPromptReplayRun harvestPromptTruth(
            String username,
            String password,
            String benchmarkRunId,
            SandboxPromptReplayScenario scenario) {
        if (!SandboxDecisionBenchmarkSettings.useRealLlm()) {
            return replayHarness.replayScenario(username, password, benchmarkRunId, scenario);
        }
        return SandboxDecisionBenchmarkExecutionMode.withMode(
                SandboxDecisionBenchmarkExecutionMode.Mode.PROMPT_HARVEST,
                () -> replayHarness.replayScenario(username, password, benchmarkRunId, scenario));
    }
}
