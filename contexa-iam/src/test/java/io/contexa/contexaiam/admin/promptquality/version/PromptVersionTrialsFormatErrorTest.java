/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.admin.promptquality.version;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionAnswerChecks;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.components.prompt.quality.QualityClosingRules;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionV1OutputInspector;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 6-5: a format error of a trial is a first answer that broke the output contract, or no usable answer; a retry
 * for a rule of the decision is no format error.
 */
class PromptVersionTrialsFormatErrorTest {

    private static Map<String, Object> retried(String reason) {
        return Map.of(PromptRuntimeTelemetrySupport.OUTPUT_RETRIES, List.of(Map.of("reason", reason, "succeeded", true)));
    }

    @Test
    void aRetryForTheContractOrNoUsableAnswerIsAFormatError() {
        assertThat(PromptVersionTrials.formatError("ALLOW", null, Map.of())).isFalse();
        assertThat(PromptVersionTrials.formatError(null, null, Map.of())).isTrue();
        assertThat(PromptVersionTrials.formatError("ALLOW", "TIMEOUT", Map.of())).isTrue();
        assertThat(PromptVersionTrials.formatError("ALLOW", null, retried(SecurityDecisionAnswerChecks.REASON_CODES_MISSING)))
                .isTrue();
        assertThat(PromptVersionTrials.formatError("ALLOW", null, retried(SecurityDecisionAnswerChecks.HYPOTHESES_MISSING)))
                .isTrue();
        assertThat(PromptVersionTrials.formatError("ALLOW", null, retried("OUTPUT_TRUNCATED"))).isTrue();
    }

    @Test
    void aRetryForARuleOfTheDecisionIsNoFormatError() {
        for (String rule : List.of(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE, SecurityDecisionFactChecks.REQUIRED_BLOCK,
                SecurityDecisionFactChecks.REQUIRED_LOW_RISK, SecurityDecisionFactChecks.REQUIRED_COVERED_WORK,
                SecurityDecisionFactChecks.REASON_CODE_MISMATCH, SecurityDecisionFactChecks.FALSE_PAST_RECORD_CLAIM,
                SecurityDecisionV1OutputInspector.MINIMUM_ACTION_VIOLATION + ": P1")) {
            assertThat(PromptVersionTrials.formatError("BLOCK", null, retried(rule))).as(rule).isFalse();
        }
    }

    @Test
    void aReplayIsKeptWithItsActionReasonTimeAndAnswerTokens() {
        SealedDecisionReplayService.Result result = new SealedDecisionReplayService.Result("req-1", "replay-1", "p1",
                "v2.0", "CHALLENGE", "new device", List.of(), null, null,
                Map.of("actualCompletionTokens", 118, PromptRuntimeTelemetrySupport.OUTPUT_RETRIES,
                        List.of(Map.of("reason", SecurityDecisionAnswerChecks.REASON_CODES_MISSING))), 5_100L, null,
                List.of());

        PromptVersionTrials.Replayed replayed = PromptVersionTrials.replayed(result);

        assertThat(replayed.action()).isEqualTo("CHALLENGE");
        assertThat(replayed.reason()).isEqualTo("new device");
        assertThat(replayed.formatError()).isTrue();
        assertThat(replayed.decisionMs()).isEqualTo(5_100L);
        assertThat(replayed.answerTokens()).isEqualTo(118);
        assertThat(replayed.failure()).isNull();
    }

    private static SealedDecisionReplayService.Result firstAnswer(String action,
                                                                  SealedDecisionReplayService.Outcome outcome,
                                                                  List<SealedDecisionReplayService.SecondPass> second) {
        return new SealedDecisionReplayService.Result("req-1", "replay-1", "p1", "v2.0", action, "first", List.of(),
                null, null, Map.of(), 5_000L, action == null ? "TIMEOUT" : null, second, outcome, action, null, null,
                null, List.of());
    }

    private static SealedDecisionReplayService.SecondPass secondPass(String requestedModel, String action,
                                                                     SealedDecisionReplayService.Outcome outcome) {
        return new SealedDecisionReplayService.SecondPass(requestedModel, action, "second", List.of(), null, null,
                Map.of(), 4_000L, null, outcome, action, null, null, null, List.of());
    }

    /**
     * Quality plan 3.10 (supplement P-9): a replay of a trial keeps the action it ends in under the closing rules: the
     * first answer's, or after an ESCALATE the second pass asked with the server's second-layer model, the first
     * action kept as it was answered.
     */
    @Test
    void aReplayKeepsItsFinalActionUnderTheClosingRules() {
        SealedDecisionReplayService.Outcome answered = SealedDecisionReplayService.Outcome.ANSWERED;
        SealedDecisionReplayService.Result settled = firstAnswer("ESCALATE", answered,
                List.of(secondPass("named-model", "BLOCK", answered), secondPass(null, "CHALLENGE", answered)));
        assertThat(PromptVersionTrials.replayed(settled).action()).isEqualTo("ESCALATE");
        assertThat(PromptVersionTrials.replayed(settled).finalAction()).isEqualTo("CHALLENGE");

        SealedDecisionReplayService.Result stillDefers = firstAnswer("ESCALATE", answered,
                List.of(secondPass(null, "ESCALATE", answered)));
        // A server that ends an ESCALATE left after the second pass with CHALLENGE, and one that lets it stay.
        assertThat(PromptVersionTrials.replayed(stillDefers, QualityClosingRules.DEFAULTS).finalAction())
                .isEqualTo("CHALLENGE");
        assertThat(PromptVersionTrials.replayed(stillDefers, new QualityClosingRules(null)).finalAction())
                .isEqualTo("ESCALATE");

        // Only a second pass under another model's name, or one the model server did not answer: no final action.
        assertThat(PromptVersionTrials.replayed(firstAnswer("ESCALATE", answered,
                List.of(secondPass("named-model", "BLOCK", answered)))).finalAction()).isNull();
        assertThat(PromptVersionTrials.replayed(firstAnswer("ESCALATE", answered, List.of(secondPass(null, null,
                SealedDecisionReplayService.Outcome.INFRASTRUCTURE_FAILURE)))).finalAction()).isNull();

        assertThat(PromptVersionTrials.replayed(firstAnswer("BLOCK", answered, List.of())).finalAction())
                .isEqualTo("BLOCK");
        assertThat(PromptVersionTrials.replayed(firstAnswer(null,
                SealedDecisionReplayService.Outcome.INFRASTRUCTURE_FAILURE, List.of())).finalAction()).isNull();
    }
}
