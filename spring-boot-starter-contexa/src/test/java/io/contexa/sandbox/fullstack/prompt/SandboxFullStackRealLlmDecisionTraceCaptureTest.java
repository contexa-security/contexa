package io.contexa.sandbox.fullstack.prompt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfSystemProperty(named = "sandbox.decision.real-llm", matches = "true")
class SandboxFullStackRealLlmDecisionTraceCaptureTest extends AbstractSandboxFullStackRealLlmDecisionBenchmarkTest {

    @Test
    @DisplayName("?ㅼ젣 LLM decision replay ?댄썑 requestId 湲곗? trace媛 prompt truth? ?④퍡 ?섏쭛?섏뼱???쒕떎")
    void shouldCaptureDecisionTraceAfterRealLlmReplay() {
        SandboxDecisionBenchmarkBatchRunner batchRunner = new SandboxDecisionBenchmarkBatchRunner(
                replayHarness,
                objectMapper,
                sandboxPromptTruthRealLlmDecisionReplayExecutor);
        SandboxPromptReplayScenario scenario = SandboxPromptReplayScenarioCatalog.resizeScenario(
                SandboxPromptReplayScenarioCatalog.ADMIN_SPARSE_HISTORY_THEN_HIGH_VALUE_REENTRY,
                3);
        SandboxDecisionBenchmarkRunResult runResult = batchRunner.execute(
                java.util.List.of(scenario),
                1,
                3,
                DEFAULT_PASSWORD).getFirst();
        SandboxPromptReplayRun replayRun = runResult.replayRun();

        for (SandboxPromptReplayRound round : replayRun.rounds()) {
            SandboxDecisionTraceSnapshot decisionSnapshot = round.decisionSnapshot();
            assertThat(decisionSnapshot).isNotNull();
            assertThat(decisionSnapshot.boundaryMode()).isEqualTo("REAL_LLM_PROMPT_REPLAY");
            assertThat(decisionSnapshot.modelId()).isEqualTo(SandboxDecisionBenchmarkSettings.pinnedModelId());
            assertThat(decisionSnapshot.requestId()).isEqualTo(round.requestId());
            assertThat(decisionSnapshot.promptExecutionMetadata()).isNotNull();
            assertThat(decisionSnapshot.systemPrompt()).isEqualTo(round.snapshot().systemPrompt());
            assertThat(decisionSnapshot.userPrompt()).isEqualTo(round.snapshot().userPrompt());
            assertThat(decisionSnapshot.promptMetadata()).containsKeys(
                    "promptVersion",
                    "promptHash",
                    "systemPromptHash",
                    "userPromptHash",
                    "promptTransformationMode",
                    "estimatedTotalTokens");
            assertThat(decisionSnapshot.pipelineMetadata()).containsKeys(
                    "boundaryMode",
                    "modelId",
                    "llmStartedAtEpochMs",
                    "llmFirstResponseAtEpochMs",
                    "llmCompletedAtEpochMs",
                    "llmLatencyMs",
                    "estimatedOutputTokens",
                    "tokensPerSecond");
            assertThat(decisionSnapshot.llmRawRequest()).isNotNull();
            assertThat(decisionSnapshot.llmRawResponse()).isNotNull();
        }
    }
}
