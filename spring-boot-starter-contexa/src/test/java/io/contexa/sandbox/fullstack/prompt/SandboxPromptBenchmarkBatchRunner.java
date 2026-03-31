package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 장기 반복 benchmark를 위한 batch replay 실행기.
 *
 * 목적:
 * - 동일한 full-stack WebClient replay를 수십, 수백 번 반복 실행할 수 있는 공통 러너를 둔다.
 * - 각 실행(run)이 독립된 사용자/메모리 체인으로 진행되도록 username과 benchmarkRunId를 분리한다.
 */
public class SandboxPromptBenchmarkBatchRunner {

    private final SandboxFullStackPromptReplayHarness replayHarness;
    private final ObjectMapper objectMapper;

    public SandboxPromptBenchmarkBatchRunner(
            SandboxFullStackPromptReplayHarness replayHarness,
            ObjectMapper objectMapper) {
        this.replayHarness = replayHarness;
        this.objectMapper = objectMapper;
    }

    public List<SandboxPromptBenchmarkRunResult> execute(
            int sampleCount,
            int roundCount,
            String password) {
        return execute(
                SandboxPromptReplayScenarioCatalog.defaultScenarios(),
                sampleCount,
                roundCount,
                password);
    }

    public List<SandboxPromptBenchmarkRunResult> execute(
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

        List<SandboxPromptBenchmarkRunResult> runResults = new ArrayList<>(sampleCount * scenarios.size());
        for (SandboxPromptReplayScenario scenario : scenarios) {
            for (int sampleIndex = 1; sampleIndex <= sampleCount; sampleIndex++) {
                String benchmarkRunId = scenario.scenarioKey().toLowerCase(Locale.ROOT)
                        + "-benchmark-run-" + sampleIndex;
                String username = String.format(
                        Locale.ROOT,
                        "benchmark-admin-%s-%03d@example.com",
                        scenario.scenarioKey().toLowerCase(Locale.ROOT).replace("_", "-"),
                        sampleIndex);

                SandboxPromptReplayRun replayRun = replayHarness.replayScenario(
                        username,
                        password,
                        benchmarkRunId,
                        expandRoundCount(scenario, roundCount));
                runResults.add(SandboxPromptBenchmarkMetricExtractor.evaluateRun(objectMapper, replayRun));
            }
        }
        return List.copyOf(runResults);
    }

    private SandboxPromptReplayScenario expandRoundCount(
            SandboxPromptReplayScenario scenario,
            int roundCount) {
        if (scenario.roundCount() == roundCount) {
            return scenario;
        }
        ArrayList<SandboxPromptRoundPlan> roundPlans = new ArrayList<>(roundCount);
        for (int roundIndex = 1; roundIndex <= roundCount; roundIndex++) {
            SandboxPromptRoundPlan sourcePlan = roundIndex <= scenario.roundCount()
                    ? scenario.roundPlanForRound(roundIndex)
                    : scenario.roundPlanForRound(scenario.roundCount());
            roundPlans.add(new SandboxPromptRoundPlan(
                    "R" + roundIndex,
                    sourcePlan.requestPath(),
                    sourcePlan.clientIp(),
                    sourcePlan.browserUserAgent(),
                    sourcePlan.simulatedUserAgentLabel(),
                    sourcePlan.deviceAlias(),
                    sourcePlan.cooldownBeforeRoundMs(),
                    sourcePlan.behaviorPhase(),
                    sourcePlan.anomalySignal(),
                    sourcePlan.expectationNote(),
                    sourcePlan.semanticMarkers()));
        }
        return new SandboxPromptReplayScenario(
                scenario.scenarioKey(),
                scenario.experimentGroup(),
                scenario.scenarioHeader(),
                scenario.expectedActionHeader(),
                scenario.userProfileKey(),
                scenario.scenarioFamily(),
                roundPlans);
    }
}
