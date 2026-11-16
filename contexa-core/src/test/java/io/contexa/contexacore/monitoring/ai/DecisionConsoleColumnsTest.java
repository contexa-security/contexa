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
package io.contexa.contexacore.monitoring.ai;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Console design 7.1: the columns a decision row gets, as the console reads them. */
class DecisionConsoleColumnsTest {

    private static Map<String, Object> meta(Object... pairs) {
        Map<String, Object> meta = new HashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            meta.put((String) pairs[i], pairs[i + 1]);
        }
        return meta;
    }

    /** Console design 5: a decision counts once; the rows of a retry, a re-judgement, a timeout and a rejection do not. */
    @Test
    void theAttemptKindSaysWhetherTheRowIsADecisionOfItsOwn() {
        assertThat(DecisionConsoleColumns.attemptKind(meta(), ZeroTrustAction.ALLOW)).isEqualTo("FIRST");
        assertThat(DecisionConsoleColumns.attemptKind(meta("judgedAgainEvent", "event-1"), ZeroTrustAction.CHALLENGE))
                .isEqualTo("AGAIN");
        assertThat(DecisionConsoleColumns.attemptKind(meta("decisionAuditPending", true), ZeroTrustAction.BLOCK))
                .isEqualTo("RETRY");
        assertThat(DecisionConsoleColumns.attemptKind(meta("decisionFailureCategory", "EVENT_TIMEOUT"),
                ZeroTrustAction.PENDING_ANALYSIS)).isEqualTo("TIMEOUT");
        assertThat(DecisionConsoleColumns.attemptKind(meta("decisionFailureCategory", "REJECTED_BACKPRESSURE"),
                ZeroTrustAction.PENDING_ANALYSIS)).isEqualTo("REJECTED");
        assertThat(DecisionConsoleColumns.attemptKind(meta("lateProcessingResultDiscarded", true), ZeroTrustAction.ALLOW))
                .as("a result that came after its time is no decision").isEqualTo("TIMEOUT");
    }

    /** Console design 6.3: no model before the engine, the engine before the model. */
    @Test
    void theSourceOfTheActionIsTheFirstThatSetIt() {
        ProcessingResult technical = ProcessingResult.builder().technicalFallbackApplied(true)
                .technicalFallbackCategory("MODEL_TIMEOUT").autonomyConstraintApplied(true)
                .autonomyConstraintReasons(List.of("LAYER2_ESCALATE_TERMINALIZED")).build();
        assertThat(DecisionConsoleColumns.decisionSource(meta(), technical, "LAYER2"))
                .containsExactly("MODEL_LESS", "MODEL_TIMEOUT");
        assertThat(DecisionConsoleColumns.decisionSource(meta(),
                ProcessingResult.builder().llmDecisionPresent(false).build(), null))
                .containsExactly("MODEL_LESS", "TECHNICAL_FALLBACK");
        assertThat(DecisionConsoleColumns.decisionSource(meta("securityDecisionContractFallbackAction", "ESCALATE"),
                ProcessingResult.builder().llmDecisionPresent(true).build(), null))
                .containsExactly("MODEL_LESS", "CONTRACT_FALLBACK");
        assertThat(DecisionConsoleColumns.decisionSource(meta(), ProcessingResult.builder().llmDecisionPresent(true)
                .responseActionFallbackApplied(true).responseActionFallbackCategory("ACTION_MISSING").build(), null))
                .containsExactly("MODEL_LESS", "ACTION_MISSING");
        assertThat(DecisionConsoleColumns.decisionSource(meta(), ProcessingResult.builder().llmDecisionPresent(true)
                .autonomyConstraintApplied(true).autonomyConstraintReasons(List.of("LAYER2_ESCALATE_TERMINALIZED"))
                .build(), "LAYER2")).containsExactly("ENGINE_CHANGED", "LAYER2_ESCALATE_TERMINALIZED");
        assertThat(DecisionConsoleColumns.decisionSource(meta(), ProcessingResult.builder().llmDecisionPresent(true)
                .build(), "ESCALATE_PROTECTION")).containsExactly("ENGINE_CHANGED", "ESCALATE_PROTECTION");
        assertThat(DecisionConsoleColumns.decisionSource(meta(), ProcessingResult.builder().llmDecisionPresent(true)
                .autonomyConstraintApplied(true).build(), "LAYER1")).containsExactly("ENGINE_CHANGED", "AUTONOMY_CONSTRAINT");
        assertThat(DecisionConsoleColumns.decisionSource(meta(), ProcessingResult.builder().llmDecisionPresent(true)
                .build(), "LAYER1")).containsExactly("MODEL", null);
    }

    @Test
    void aSynchronousDecisionTakesEffectBeforeTheResponseAndAQueuedOneFromTheNextRequest() {
        assertThat(DecisionConsoleColumns.enforcementTiming(meta("protectableSync", true, "stripeId", 3)))
                .isEqualTo("BEFORE_RESPONSE");
        assertThat(DecisionConsoleColumns.enforcementTiming(meta("analysisQueuedAt", 1L))).isEqualTo("NEXT_REQUEST");
        assertThat(DecisionConsoleColumns.enforcementTiming(meta("stripeId", 3))).isEqualTo("NEXT_REQUEST");
        assertThat(DecisionConsoleColumns.enforcementTiming(meta())).isEqualTo("BEFORE_RESPONSE");
    }

    @Test
    void theActorIsAPersonAnAgentOrAService() {
        assertThat(DecisionConsoleColumns.actorKind("DELEGATED_AGENT")).isEqualTo("AGENT");
        assertThat(DecisionConsoleColumns.actorKind("autonomous_agent")).isEqualTo("AGENT");
        assertThat(DecisionConsoleColumns.actorKind("SERVICE_CLIENT")).isEqualTo("SERVICE");
        assertThat(DecisionConsoleColumns.actorKind("HUMAN")).isEqualTo("HUMAN");
        assertThat(DecisionConsoleColumns.actorKind(null)).isNull();
    }

    @Test
    void theMostLikelyExplanationIsTheOneTheModelMarkedSo() {
        ProcessingResult result = ProcessingResult.builder().hypotheses(List.of(
                Map.of("id", "H1", "assessment", "POSSIBLE"),
                Map.of("id", "h2", "assessment", "most_likely"),
                Map.of("id", "H3", "assessment", "MOST_LIKELY"))).build();

        assertThat(DecisionConsoleColumns.mostLikely(result)).isEqualTo("H2");
        assertThat(DecisionConsoleColumns.mostLikely(ProcessingResult.builder().build())).isNull();
    }

    @Test
    void theModelCallsAreOnePerLayerAndOnePerCorrectiveRetry() {
        assertThat(DecisionConsoleColumns.modelCalls(meta("modelCallStages", List.of("LAYER1", "LAYER2"),
                "securityDecisionOutputRetries", List.of("CONTRACT")))).isEqualTo(3);
        assertThat(DecisionConsoleColumns.modelCalls(meta("modelCallStages", List.of("LAYER1")))).isEqualTo(1);
        assertThat(DecisionConsoleColumns.modelCalls(meta())).as("unknown, not zero").isNull();
    }

    /** The wait of a person is measured only where the person waited: a decision taken before the response. */
    @Test
    void theUserWaitAndTheTokensAreReadFromTheDecision() {
        Instant now = Instant.ofEpochMilli(10_000L);
        DecisionConsoleColumns.Values synchronous = DecisionConsoleColumns.of(meta("protectableSync", true,
                "ingestAt", 7_500L, "layer1ActualPromptTokens", 1_200, "layer2ActualPromptTokens", 800,
                "cachedPromptTokens", 300, "actualCompletionTokens", "90"), null, ZeroTrustAction.ALLOW, now);
        DecisionConsoleColumns.Values queued = DecisionConsoleColumns.of(meta("analysisQueuedAt", 1L, "ingestAt", 7_500L,
                "actualPromptTokens", 500), null, ZeroTrustAction.ALLOW, now);

        assertThat(synchronous.userWaitMs()).isEqualTo(2_500L);
        assertThat(synchronous.promptTokens()).isEqualTo(2_000L);
        assertThat(synchronous.cachedPromptTokens()).isEqualTo(300L);
        assertThat(synchronous.outputTokens()).isEqualTo(90L);
        assertThat(queued.userWaitMs()).as("nobody waited for a queued decision").isNull();
        assertThat(queued.promptTokens()).isEqualTo(500L);
    }

    /** The reasons keep the model's order and the group their code belongs to. */
    @Test
    void theReasonsKeepTheModelsOrderAndTheirGroup() {
        ProcessingResult result = ProcessingResult.builder().reasonCodes(List.of(
                new SecurityDecisionOutputContract.Citation("DEVIATION_DEVICE", "F3"),
                new SecurityDecisionOutputContract.Citation("DEVIATION_NETWORK", "F4"))).build();

        List<DecisionConsoleColumns.Reason> reasons = DecisionConsoleColumns.reasons(result, null);

        assertThat(reasons).extracting(DecisionConsoleColumns.Reason::rank).containsExactly(1, 2);
        assertThat(reasons).extracting(DecisionConsoleColumns.Reason::code)
                .containsExactly("DEVIATION_DEVICE", "DEVIATION_NETWORK");
        assertThat(reasons).extracting(DecisionConsoleColumns.Reason::factId).containsExactly("F3", "F4");
        assertThat(reasons).extracting(DecisionConsoleColumns.Reason::group).doesNotContainNull();
    }
}
