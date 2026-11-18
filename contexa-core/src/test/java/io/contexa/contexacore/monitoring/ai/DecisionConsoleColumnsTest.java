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
import io.contexa.contexacore.autonomous.baseline.BaselineView;
import io.contexa.contexacore.autonomous.context.decision.DeviationDimension;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
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

    /** K25: only the model's own sentence is kept as its words; the sentence the engine wrote or added is the engine's. */
    @Test
    void theModelsSentenceIsKeptApartFromTheEngines() {
        String added = "Layer2 returned ESCALATE, so final autonomous action was terminalized to CHALLENGE by tiered "
                + "strategy policy.";
        ProcessingResult model = ProcessingResult.builder().reasoning("A device the user never used.")
                .fieldProvenance(Map.of("reasoning", "MODEL")).build();
        ProcessingResult changed = ProcessingResult.builder().reasoning("A device the user never used.\n" + added)
                .autonomyConstraintSummary(added).fieldProvenance(Map.of("reasoning", "MODEL")).build();
        ProcessingResult engineOnly = ProcessingResult.builder().reasoning(added).autonomyConstraintSummary(added).build();
        ProcessingResult fallback = ProcessingResult.builder().reasoning("[AI Native] Layer2 LLM call failed")
                .fieldProvenance(Map.of("reasoning", "PLATFORM_FALLBACK")).build();
        ProcessingResult canonical = ProcessingResult.builder().reasoning("The baseline is limited.")
                .llmReasoning("The baseline is established.").fieldProvenance(Map.of("reasoning", "PLATFORM_CANONICAL"))
                .build();
        ProcessingResult modelLess = ProcessingResult.builder()
                .reasoning("Escalate overload protection - CHALLENGE applied").build();

        assertThat(DecisionConsoleColumns.sentences(model, "MODEL"))
                .containsExactly("A device the user never used.", null);
        assertThat(DecisionConsoleColumns.sentences(changed, "ENGINE_CHANGED"))
                .containsExactly("A device the user never used.", added);
        assertThat(DecisionConsoleColumns.sentences(engineOnly, "MODEL_LESS")).containsExactly(null, added);
        assertThat(DecisionConsoleColumns.sentences(engineOnly, "ENGINE_CHANGED")).containsExactly(null, added);
        assertThat(DecisionConsoleColumns.sentences(fallback, "MODEL"))
                .containsExactly(null, "[AI Native] Layer2 LLM call failed");
        assertThat(DecisionConsoleColumns.sentences(canonical, "MODEL"))
                .containsExactly("The baseline is established.", "The baseline is limited.");
        assertThat(DecisionConsoleColumns.sentences(modelLess, "MODEL_LESS"))
                .containsExactly(null, "Escalate overload protection - CHALLENGE applied");
        assertThat(DecisionConsoleColumns.summary(changed, null, Map.of(), List.of(), null, "ENGINE_CHANGED", List.of()))
                .containsEntry("modelReason", "A device the user never used.").containsEntry("engineReason", added)
                .doesNotContainKey("reason");
    }

    /** K27: the usual values of each dimension, as the baseline view the prompt read holds them. */
    @Test
    void theUsualValuesComeFromTheBaselineViewInTheNotationOfTheRequestsValue() {
        Map<String, Integer> actions = new LinkedHashMap<>();
        actions.put("READ", 20);
        actions.put("EXPORT", 30);
        BaselineView view = new BaselineView(BaselineView.State.ESTABLISHED, 46L, 46, 12, 30, "basis",
                List.of(9, 10, 11, 14), List.of(9, 10, 11, 14), List.of(1, 2, 3), List.of(1, 2, 3),
                List.of("projectKey=PLM-OPS"), actions, null, null, List.of("INTERNAL=25", "CRITICAL=3"), null, null, 0,
                List.of(), List.of("10.1.2.0/24"), List.of("Safari/17 on MAC"), List.of("Safari"), List.of("MAC"),
                List.of("PASSWORD"), BaselineView.EvidenceGrade.STRONG, List.of());

        assertThat(DecisionConsoleColumns.usualValues(view, DeviationDimension.TIME))
                .containsExactly("09", "10", "11", "14");
        assertThat(DecisionConsoleColumns.usualValues(view, DeviationDimension.DAY)).containsExactly("Mon", "Tue", "Wed");
        assertThat(DecisionConsoleColumns.usualValues(view, DeviationDimension.NETWORK)).containsExactly("10.1.2.0/24");
        assertThat(DecisionConsoleColumns.usualValues(view, DeviationDimension.DEVICE))
                .containsExactly("Safari/17 on MAC");
        assertThat(DecisionConsoleColumns.usualValues(view, DeviationDimension.LOGIN_METHOD)).containsExactly("PASSWORD");
        assertThat(DecisionConsoleColumns.usualValues(view, DeviationDimension.TARGET))
                .containsExactly("projectKey=PLM-OPS");
        assertThat(DecisionConsoleColumns.usualValues(view, DeviationDimension.ACTION)).as("the most frequent first")
                .containsExactly("EXPORT", "READ");
        assertThat(DecisionConsoleColumns.usualValues(view, DeviationDimension.RESOURCE_CLASS))
                .containsExactly("NORMAL", "CRITICAL");
        assertThat(DecisionConsoleColumns.usualValues(view, DeviationDimension.SIZE)).isEmpty();
        assertThat(DecisionConsoleColumns.usualValues(null, DeviationDimension.TIME)).isEmpty();
    }

    /** K17 (D11): the rules the model's answers still broke reach the summary, and the row asks for a review. */
    @Test
    void theRulesTheAnswersStillBrokeReachTheSummaryAndAskForAReview() {
        Map<String, Object> meta = meta(PromptRuntimeTelemetrySupport.RULE_BREACHES, List.of(
                Map.of("layer", "Layer1", "rule", "REQUIRED_BLOCK_BOUNDARY_ACTION_MISMATCH"),
                Map.of("layer", "Layer2", "rule", "MINIMUM_ACTION_VIOLATION: MIN_P1_IDENTITY_DEVIATION requires "
                        + "CHALLENGE or a stronger action")));
        ProcessingResult result = ProcessingResult.builder().success(true).action("ALLOW").build();

        DecisionConsoleColumns.Values broken = DecisionConsoleColumns.of(meta, result, ZeroTrustAction.ALLOW,
                Instant.now());
        DecisionConsoleColumns.Values kept = DecisionConsoleColumns.of(meta(), result, ZeroTrustAction.ALLOW,
                Instant.now());

        assertThat(broken.ruleBroken()).isTrue();
        assertThat(kept.ruleBroken()).isFalse();
        assertThat(kept.summary()).doesNotContainKey("ruleBreaches");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> breaches = (List<Map<String, Object>>) broken.summary().get("ruleBreaches");
        assertThat(breaches).hasSize(2);
        assertThat(breaches.get(0)).containsEntry("layer", "Layer1")
                .containsEntry("codes", List.of("REQUIRED_BLOCK_BOUNDARY_ACTION_MISMATCH"));
        assertThat(breaches.get(1).get("codes")).as("the floor and its rule, not the action it names")
                .isEqualTo(List.of("MINIMUM_ACTION_VIOLATION", "MIN_P1_IDENTITY_DEVIATION"));
    }
}
