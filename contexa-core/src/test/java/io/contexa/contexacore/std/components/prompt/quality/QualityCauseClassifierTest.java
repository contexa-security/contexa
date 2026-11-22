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
package io.contexa.contexacore.std.components.prompt.quality;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static io.contexa.contexacore.std.components.prompt.quality.QualityCauseCheck.State.APPLIES;
import static io.contexa.contexacore.std.components.prompt.quality.QualityCauseCheck.State.CLEAR;
import static io.contexa.contexacore.std.components.prompt.quality.QualityCauseCheck.State.NOT_COMPUTED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Quality plan 3.5: each of the seven rules applies, does not apply and cannot be computed where its record says so;
 * an answer is put down to the first cause that applies in the order of precedence; the same record gives the same
 * cause; and the real measurement of the default set (version v1.0, 70 cases, one run) is put down to its causes.
 */
class QualityCauseClassifierTest {

    private static final long LIMIT = 90_000L;
    private static final Set<QualityAction> STOP = QualityFixtures.STOP;
    private static final QualityCauseCitations RIGHT = citations(3, 3, 0);

    // ----- fixtures -----

    /** A threat whose prompt names the unknown facts and draws at the context level. */
    private static QualityCase threat(List<String> decidingFacts, List<String> unknown, String level) {
        return item("T1", QualityCaseClass.THREAT, STOP, decidingFacts, unknown, level);
    }

    private static QualityCase item(String key, QualityCaseClass classification, Set<QualityAction> allowed,
                                    List<String> decidingFacts, List<String> unknown, String level) {
        ObjectNode context = QualityFixtures.JSON.createObjectNode();
        ArrayNode names = context.putObject("decisionFacts").putArray("unknown");
        unknown.forEach(names::add);
        if (level != null) {
            context.putObject("coverage").put("level", level);
        }
        return new QualityCase(key, QualityFixtures.input(context), new QualityCaseExpectation(allowed, null,
                classification, classification == QualityCaseClass.NORMAL ? QualityCaseKind.NORMAL_WORK
                : QualityCaseKind.OUTSIDER, new QualityCaseRationale(null, "A case of the tests."), decidingFacts),
                QualityCaseGrade.ORDINARY, null, new QualityCaseEnvironment("UTC", "1"), QualityCaseOrigin.CONTEXA,
                null);
    }

    private static QualityCase plainThreat() {
        return threat(List.of(), List.of("PeerCohort"), "BUSINESS_AWARE");
    }

    private static QualityCauseCitations citations(int cited, int present, int flagged) {
        return new QualityCauseCitations(true, cited, present, flagged, List.of());
    }

    private static QualityCauseAnswer answer(int run, QualityAction first, QualityAction model, QualityAction last,
                                             QualityCauseCitations citations, Long callMillis) {
        List<Long> calls = new ArrayList<>();
        calls.add(callMillis);
        return new QualityCauseAnswer("T1", run, first, model, last, false, false, citations, calls,
                callMillis != null ? callMillis + 200 : null, false);
    }

    /** A first answer that allows a threat, as the model gave it and as it stood. */
    private static QualityCauseAnswer allowed(QualityCauseCitations citations) {
        return answer(1, QualityAction.ALLOW, QualityAction.ALLOW, QualityAction.ALLOW, citations, 6_000L);
    }

    private static QualityCauseResult classify(QualityCase item, QualityCauseAnswer answer) {
        return QualityCauseClassifier.measured(item, answer, List.of(answer), LIMIT);
    }

    private static QualityCauseDecision decision(String source, QualityAction proposed, QualityAction last,
                                                 QualityCauseCitations citations,
                                                 QualityCauseDecision.SourceTruth truth, String level) {
        return new QualityCauseDecision(source, null, proposed, last, true, false, false, false, false, level,
                List.of("OnCall"), citations, truth, "MISSED_SIGNAL");
    }

    private static QualityCauseDecision modelDecision(QualityCauseCitations citations) {
        return decision(QualityCauseDecision.SOURCE_MODEL, QualityAction.ALLOW, QualityAction.ALLOW, citations,
                QualityCauseDecision.SourceTruth.inspected(4, 0, 0), "BUSINESS_AWARE");
    }

    // ----- which answers are wrong -----

    @Test
    void anAnswerIsWrongOnTheActionOutsideTheAnswerAndAFailedMeasurementSaysNothing() {
        QualityCase item = plainThreat();
        assertThat(QualityCauseClassifier.wrongOn(item, answer(1, QualityAction.BLOCK, QualityAction.BLOCK,
                QualityAction.BLOCK, RIGHT, 6_000L))).isEmpty();
        assertThat(QualityCauseClassifier.wrongOn(item, allowed(RIGHT))).contains(QualityCauseBasis.BOTH);
        assertThat(QualityCauseClassifier.wrongOn(item, answer(1, QualityAction.ESCALATE, QualityAction.ESCALATE,
                QualityAction.ALLOW, RIGHT, 6_000L))).contains(QualityCauseBasis.FINAL);
        QualityCase normal = item("N1", QualityCaseClass.NORMAL, QualityFixtures.PASS, List.of(), List.of(),
                "BUSINESS_AWARE");
        assertThat(QualityCauseClassifier.wrongOn(normal, new QualityCauseAnswer("N1", 1, QualityAction.ESCALATE,
                QualityAction.ESCALATE, QualityAction.ALLOW, false, false, RIGHT, List.of(6_000L), 6_200L, false)))
                .contains(QualityCauseBasis.FIRST_ANSWER);
        // No action of the four is no answer, wrong on the first answer.
        assertThat(QualityCauseClassifier.wrongOn(item, answer(1, null, null, null, RIGHT, 6_000L)))
                .contains(QualityCauseBasis.FIRST_ANSWER);
        assertThat(QualityCauseClassifier.wrongOn(item, new QualityCauseAnswer("T1", 1, null, null, null, false,
                false, null, List.of(), null, true))).isEmpty();
        assertThatThrownBy(() -> classify(item, answer(1, QualityAction.BLOCK, QualityAction.BLOCK,
                QualityAction.BLOCK, RIGHT, 6_000L))).isInstanceOf(IllegalArgumentException.class);
    }

    // ----- format and model -----

    @Test
    void formatAndModelAppliesToNoAnswerAReplacedAnswerAnUnusableSecondPassAndACallOverTheDecisionsLimit() {
        QualityCase item = plainThreat();
        QualityCauseResult none = classify(item, answer(1, null, null, null, RIGHT, 6_000L));
        assertThat(none.cause()).isEqualTo(QualityCause.FORMAT_AND_MODEL);
        assertThat(none.check(QualityCause.FORMAT_AND_MODEL).reason()).isEqualTo(QualityCauseClassifier.NO_ANSWER);

        QualityCauseAnswer replaced = new QualityCauseAnswer("T1", 1, QualityAction.ALLOW, null, QualityAction.ALLOW,
                true, false, RIGHT, List.of(6_000L, 7_000L), 13_500L, false);
        assertThat(classify(item, replaced).check(QualityCause.FORMAT_AND_MODEL))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(APPLIES, QualityCauseClassifier.MODEL_ANSWER_UNUSABLE);

        QualityCauseAnswer secondPass = new QualityCauseAnswer("T1", 1, QualityAction.ESCALATE,
                QualityAction.ESCALATE, QualityAction.ALLOW, false, true, RIGHT, List.of(6_000L), 9_000L, false);
        assertThat(classify(item, secondPass).check(QualityCause.FORMAT_AND_MODEL).reason())
                .isEqualTo(QualityCauseClassifier.SECOND_PASS_UNUSABLE);

        // 95 seconds is well within the replay's own limit, and over the 90 seconds of the decisions.
        QualityCauseResult slow = classify(item, answer(1, QualityAction.ALLOW, QualityAction.ALLOW,
                QualityAction.ALLOW, RIGHT, 95_000L));
        assertThat(slow.cause()).isEqualTo(QualityCause.FORMAT_AND_MODEL);
        assertThat(slow.check(QualityCause.FORMAT_AND_MODEL).details())
                .containsExactly("reason=OVER_TIME_LIMIT", "call1Ms=95000", "limitMs=90000");
    }

    @Test
    void formatAndModelIsClearWithinTheLimitAndNotComputedWithoutALimitOrACallTime() {
        QualityCase item = plainThreat();
        assertThat(classify(item, allowed(RIGHT)).check(QualityCause.FORMAT_AND_MODEL))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(CLEAR, QualityCauseClassifier.MODEL_ANSWER_USED);
        QualityCauseAnswer answer = allowed(RIGHT);
        assertThat(QualityCauseClassifier.measured(item, answer, List.of(answer), 0).check(
                QualityCause.FORMAT_AND_MODEL)).extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(NOT_COMPUTED, QualityCauseClassifier.TIME_LIMIT_UNKNOWN);
        QualityCauseAnswer unmeasuredSlow = new QualityCauseAnswer("T1", 1, QualityAction.ALLOW, QualityAction.ALLOW,
                QualityAction.ALLOW, false, false, RIGHT, List.of(), 120_000L, false);
        assertThat(classify(item, unmeasuredSlow).check(QualityCause.FORMAT_AND_MODEL))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(NOT_COMPUTED, QualityCauseClassifier.CALL_TIME_UNKNOWN);
        // The replay as a whole within the limit: none of its calls ran over it.
        QualityCauseAnswer unmeasuredFast = new QualityCauseAnswer("T1", 1, QualityAction.ALLOW, QualityAction.ALLOW,
                QualityAction.ALLOW, false, false, RIGHT, List.of(), 8_000L, false);
        assertThat(classify(item, unmeasuredFast).check(QualityCause.FORMAT_AND_MODEL).state()).isEqualTo(CLEAR);
    }

    // ----- engine changed -----

    @Test
    void engineChangedAppliesWhenTheModelsOwnActionWasRightAndARuleChangedIt() {
        QualityCase item = plainThreat();
        // The first answer deferred, which is right; the closing rules ended it in ALLOW. The citations are wrong too.
        QualityCauseResult changed = classify(item, answer(1, QualityAction.ESCALATE, QualityAction.ESCALATE,
                QualityAction.ALLOW, citations(3, 2, 1), 6_000L));
        assertThat(changed.cause()).isEqualTo(QualityCause.ENGINE_CHANGED);
        assertThat(changed.basis()).isEqualTo(QualityCauseBasis.FINAL);
        assertThat(changed.check(QualityCause.ENGINE_CHANGED).details()).containsExactly("model=ESCALATE",
                "action=ALLOW");
        assertThat(changed.check(QualityCause.GROUNDING_ERROR).state()).isEqualTo(APPLIES);

        assertThat(classify(item, allowed(RIGHT)).check(QualityCause.ENGINE_CHANGED))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(CLEAR, QualityCauseClassifier.MODEL_ACTION_WRONG);
        assertThat(classify(item, answer(1, QualityAction.ALLOW, null, QualityAction.ALLOW, RIGHT, 6_000L))
                .check(QualityCause.ENGINE_CHANGED)).extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(NOT_COMPUTED, QualityCauseClassifier.NO_MODEL_ACTION);
    }

    // ----- input error -----

    @Test
    void inputErrorIsADecisionsOnlyAndComesOnlyFromASealTheEvidenceAuditCompared() {
        assertThat(classify(plainThreat(), allowed(RIGHT)).check(QualityCause.INPUT_ERROR))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(CLEAR, QualityCauseClassifier.DECISIONS_ONLY);

        QualityCauseResult mismatch = QualityCauseClassifier.rated(decision(QualityCauseDecision.SOURCE_MODEL,
                QualityAction.ALLOW, QualityAction.ALLOW, RIGHT, QualityCauseDecision.SourceTruth.inspected(3, 1, 0),
                "BUSINESS_AWARE"));
        assertThat(mismatch.cause()).isEqualTo(QualityCause.INPUT_ERROR);
        assertThat(mismatch.check(QualityCause.INPUT_ERROR).details()).containsExactly("matched=3", "mismatched=1",
                "unverifiable=0");
        assertThat(QualityCauseClassifier.rated(modelDecision(RIGHT)).check(QualityCause.INPUT_ERROR))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(CLEAR, QualityCauseClassifier.SOURCE_MATCHED);
        Map<QualityCauseDecision.SourceTruth, String> notComputed = Map.of(
                QualityCauseDecision.SourceTruth.NOT_SEALED, QualityCauseClassifier.NOT_SEALED,
                QualityCauseDecision.SourceTruth.NOT_INSPECTED, QualityCauseClassifier.NOT_INSPECTED,
                QualityCauseDecision.SourceTruth.inspected(0, 0, 5), QualityCauseClassifier.NOT_COMPARED);
        notComputed.forEach((truth, reason) -> assertThat(QualityCauseClassifier.rated(decision(
                QualityCauseDecision.SOURCE_MODEL, QualityAction.ALLOW, QualityAction.ALLOW, RIGHT, truth,
                "BUSINESS_AWARE")).check(QualityCause.INPUT_ERROR))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(NOT_COMPUTED, reason));
    }

    // ----- input shortage -----

    @Test
    void inputShortageAppliesToADecidingFactTheUnknownListNamesOrALowContext() {
        QualityCauseResult path = classify(threat(List.of("frictionProfile.onCall.onCall=false",
                "session.mfaVerified=false"), List.of("OnCall", "PeerCohort"), "BUSINESS_AWARE"), allowed(RIGHT));
        assertThat(path.cause()).isEqualTo(QualityCause.INPUT_SHORTAGE);
        assertThat(path.check(QualityCause.INPUT_SHORTAGE).reason())
                .isEqualTo(QualityCauseClassifier.DECIDING_FACT_UNKNOWN);
        assertThat(path.check(QualityCause.INPUT_SHORTAGE).details()).containsExactly(
                "fact=frictionProfile.onCall.onCall=false", "level=BUSINESS_AWARE", "unknown=OnCall",
                "unknown=PeerCohort");
        assertThat(classify(threat(List.of("oncall"), List.of("OnCall"), "BUSINESS_AWARE"), allowed(RIGHT))
                .check(QualityCause.INPUT_SHORTAGE).state()).isEqualTo(APPLIES);
        // A low context alone suffices, deciding facts listed or not.
        for (String low : List.of("ENVIRONMENT_ONLY", "IDENTITY_AWARE")) {
            assertThat(classify(threat(List.of(), List.of(), low), allowed(RIGHT)).check(QualityCause.INPUT_SHORTAGE))
                    .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                    .containsExactly(APPLIES, QualityCauseClassifier.CONTEXT_LEVEL_LOW);
        }
    }

    @Test
    void inputShortageIsClearOnlyForACaseThatListsItsDecidingFactsAndNotComputedOtherwise() {
        assertThat(classify(threat(List.of("session.mfaVerified=false"), List.of("OnCall"), "SCOPE_AWARE"),
                allowed(RIGHT)).check(QualityCause.INPUT_SHORTAGE))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(CLEAR, QualityCauseClassifier.DECIDING_FACTS_KNOWN);
        assertThat(classify(plainThreat(), allowed(RIGHT)).check(QualityCause.INPUT_SHORTAGE))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(NOT_COMPUTED, QualityCauseClassifier.NO_DECIDING_FACTS);
        assertThat(classify(threat(List.of("session.mfaVerified=false"), List.of(), null), allowed(RIGHT))
                .check(QualityCause.INPUT_SHORTAGE).reason()).isEqualTo(QualityCauseClassifier.NO_CONTEXT_LEVEL);
        // A decision lists no deciding fact: a low context applies, any other is not computed.
        assertThat(QualityCauseClassifier.rated(modelDecision(RIGHT)).check(QualityCause.INPUT_SHORTAGE))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(NOT_COMPUTED, QualityCauseClassifier.NO_DECIDING_FACTS);
    }

    // ----- grounding error -----

    @Test
    void groundingErrorAppliesToAFactNotInThePromptOrALineThatDoesNotSayIt() {
        QualityCase item = plainThreat();
        QualityCauseCitations notInPrompt = new QualityCauseCitations(true, 3, 2, 0, List.of(
                new QualityCauseCitations.Finding("BASELINE_MATCH", "B1", "MATCH", true),
                new QualityCauseCitations.Finding("DEVIATION_TIME", "F9", "MISMATCH", false),
                new QualityCauseCitations.Finding("RECORD_COVERS_WORK", "F2", "UNDECIDED", true)));
        QualityCauseResult missing = classify(item, allowed(notInPrompt));
        assertThat(missing.cause()).isEqualTo(QualityCause.GROUNDING_ERROR);
        assertThat(missing.check(QualityCause.GROUNDING_ERROR).reason())
                .isEqualTo(QualityCauseClassifier.CITATION_NOT_IN_PROMPT);
        assertThat(missing.check(QualityCause.GROUNDING_ERROR).details()).containsExactly("cited=3", "notInPrompt=1",
                "doesNotSayIt=0", "notInPromptFact=F9");
        assertThat(classify(item, allowed(citations(3, 3, 1))).check(QualityCause.GROUNDING_ERROR).reason())
                .isEqualTo(QualityCauseClassifier.CITATION_DOES_NOT_SAY_IT);
        // A citation the facts could not decide is not a wrong one.
        QualityCauseCitations undecided = new QualityCauseCitations(true, 1, 1, 0, List.of(
                new QualityCauseCitations.Finding("RECORD_COVERS_WORK", "F2", "UNDECIDED", true)));
        assertThat(classify(item, allowed(undecided)).check(QualityCause.GROUNDING_ERROR).state()).isEqualTo(CLEAR);
        assertThat(classify(item, allowed(citations(0, 0, 0))).check(QualityCause.GROUNDING_ERROR).reason())
                .isEqualTo(QualityCauseClassifier.NO_CITATION);
        assertThat(classify(item, allowed(QualityCauseCitations.NOT_CHECKED)).check(QualityCause.GROUNDING_ERROR))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(NOT_COMPUTED, QualityCauseClassifier.CITATIONS_NOT_CHECKED);
    }

    // ----- unstable -----

    @Test
    void unstableAppliesToACaseWhoseRunsGiveOtherActionsAndNeedsTwoRuns() {
        QualityCase item = plainThreat();
        QualityCauseAnswer first = answer(1, QualityAction.ALLOW, QualityAction.ALLOW, QualityAction.ALLOW, RIGHT,
                6_000L);
        List<QualityCauseAnswer> differing = List.of(first, answer(2, QualityAction.BLOCK, QualityAction.BLOCK,
                QualityAction.BLOCK, RIGHT, 6_000L), answer(3, QualityAction.ALLOW, QualityAction.ALLOW,
                QualityAction.ALLOW, RIGHT, 6_000L));
        QualityCauseResult unstable = QualityCauseClassifier.measured(item, first, differing, LIMIT);
        assertThat(unstable.cause()).isEqualTo(QualityCause.UNSTABLE);
        assertThat(unstable.check(QualityCause.UNSTABLE).details()).containsExactly("run1=ALLOW", "run2=BLOCK",
                "run3=ALLOW");
        List<QualityCauseAnswer> steady = List.of(first, answer(2, QualityAction.ALLOW, QualityAction.ALLOW,
                QualityAction.ALLOW, RIGHT, 6_000L));
        assertThat(QualityCauseClassifier.measured(item, first, steady, LIMIT).check(QualityCause.UNSTABLE))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(CLEAR, QualityCauseClassifier.SAME_ACTION_EVERY_RUN);
        assertThat(classify(item, first).check(QualityCause.UNSTABLE))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(NOT_COMPUTED, QualityCauseClassifier.ONE_RUN);
        assertThat(QualityCauseClassifier.rated(modelDecision(RIGHT)).check(QualityCause.UNSTABLE))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(NOT_COMPUTED, QualityCauseClassifier.ONE_DECISION);
    }

    // ----- judgement error -----

    @Test
    void judgementErrorAppliesToRightCitationsAndAnActionOutsideTheAnswer() {
        QualityCase item = plainThreat();
        QualityCauseResult judged = classify(item, allowed(RIGHT));
        assertThat(judged.cause()).isEqualTo(QualityCause.JUDGEMENT_ERROR);
        assertThat(judged.check(QualityCause.JUDGEMENT_ERROR).details()).containsExactly("action=ALLOW",
                "allowed=CHALLENGE|ESCALATE|BLOCK");
        assertThat(classify(item, allowed(citations(2, 2, 1))).check(QualityCause.JUDGEMENT_ERROR))
                .extracting(QualityCauseCheck::state, QualityCauseCheck::reason)
                .containsExactly(CLEAR, QualityCauseClassifier.CITATION_WRONG);
        // Nothing applies, and the two that might could not be computed: an administrator puts it down to one.
        QualityCauseResult unclassified = classify(item, allowed(QualityCauseCitations.NOT_CHECKED));
        assertThat(unclassified.check(QualityCause.JUDGEMENT_ERROR).state()).isEqualTo(NOT_COMPUTED);
        assertThat(unclassified.cause()).isEqualTo(QualityCause.UNCLASSIFIED);
        assertThat(QualityCause.JUDGEMENT_ERROR.fix().opensVersionEditor()).isTrue();
        assertThat(QualityCause.RULED.stream().filter(cause -> cause.fix().opensVersionEditor()).toList())
                .containsExactly(QualityCause.JUDGEMENT_ERROR);
    }

    // ----- precedence and determinism -----

    @Test
    void anAnswerUnderSeveralCausesIsPutDownToTheFirstInTheOrderOfPrecedence() {
        assertThat(QualityCause.RULED).containsExactly(QualityCause.FORMAT_AND_MODEL, QualityCause.ENGINE_CHANGED,
                QualityCause.INPUT_ERROR, QualityCause.INPUT_SHORTAGE, QualityCause.GROUNDING_ERROR,
                QualityCause.UNSTABLE, QualityCause.JUDGEMENT_ERROR);
        QualityCauseCitations wrong = citations(3, 3, 1);
        // Format and model before engine changed: the engine replaced an answer that broke the contract, the
        // model's retry had been right.
        QualityCauseResult replaced = classify(plainThreat(), new QualityCauseAnswer("T1", 1, QualityAction.ALLOW,
                QualityAction.BLOCK, QualityAction.ALLOW, true, false, wrong, List.of(6_000L, 7_000L), 13_500L,
                false));
        assertThat(replaced.check(QualityCause.ENGINE_CHANGED).state()).isEqualTo(APPLIES);
        assertThat(replaced.cause()).isEqualTo(QualityCause.FORMAT_AND_MODEL);
        // Input error before input shortage before grounding error, on a decision.
        QualityCauseResult decided = QualityCauseClassifier.rated(decision(QualityCauseDecision.SOURCE_MODEL,
                QualityAction.ALLOW, QualityAction.ALLOW, wrong, QualityCauseDecision.SourceTruth.inspected(1, 2, 0),
                "IDENTITY_AWARE"));
        assertThat(decided.checks()).extracting(QualityCauseCheck::state).containsExactly(CLEAR, CLEAR, APPLIES,
                APPLIES, APPLIES, NOT_COMPUTED, CLEAR);
        assertThat(decided.cause()).isEqualTo(QualityCause.INPUT_ERROR);
        // Input shortage before grounding error before unstable, on a measured answer.
        QualityCase short1 = threat(List.of("OnCall"), List.of("OnCall"), "BUSINESS_AWARE");
        QualityCauseAnswer first = allowed(wrong);
        List<QualityCauseAnswer> runs = List.of(first, answer(2, QualityAction.BLOCK, QualityAction.BLOCK,
                QualityAction.BLOCK, RIGHT, 6_000L));
        assertThat(QualityCauseClassifier.measured(short1, first, runs, LIMIT).cause())
                .isEqualTo(QualityCause.INPUT_SHORTAGE);
        assertThat(QualityCauseClassifier.measured(plainThreat(), first, runs, LIMIT).cause())
                .isEqualTo(QualityCause.GROUNDING_ERROR);
        // Unstable before judgement error.
        QualityCauseAnswer rightCitations = allowed(RIGHT);
        assertThat(QualityCauseClassifier.measured(plainThreat(), rightCitations, List.of(rightCitations,
                runs.get(1)), LIMIT).cause()).isEqualTo(QualityCause.UNSTABLE);
        assertThatThrownBy(() -> new QualityCauseResult(QualityCause.UNCLASSIFIED, null, List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theSameRecordGivesTheSameCause() {
        QualityCase item = threat(List.of("OnCall"), List.of("OnCall"), "IDENTITY_AWARE");
        QualityCauseAnswer answer = allowed(citations(3, 2, 1));
        assertThat(classify(item, answer)).isEqualTo(classify(item, answer));
        QualityCauseDecision decision = decision(QualityCauseDecision.SOURCE_ENGINE_CHANGED, QualityAction.CHALLENGE,
                QualityAction.BLOCK, RIGHT, QualityCauseDecision.SourceTruth.NOT_INSPECTED, "SCOPE_AWARE");
        assertThat(QualityCauseClassifier.rated(decision)).isEqualTo(QualityCauseClassifier.rated(decision));
    }

    // ----- decisions -----

    @Test
    void aDecisionIsPutDownToTheCauseItsRecordStates() {
        QualityCauseDecision modelLess = new QualityCauseDecision(QualityCauseDecision.SOURCE_MODEL_LESS,
                "CONTRACT_FALLBACK", null, QualityAction.CHALLENGE, true, false, false, false, false,
                "BUSINESS_AWARE", List.of(), RIGHT, null, null);
        QualityCauseResult fallback = QualityCauseClassifier.rated(modelLess);
        assertThat(fallback.cause()).isEqualTo(QualityCause.FORMAT_AND_MODEL);
        assertThat(fallback.check(QualityCause.FORMAT_AND_MODEL).details()).containsExactly("reason=MODEL_LESS",
                "cause=CONTRACT_FALLBACK");
        assertThat(fallback.basis()).isNull();
        QualityCauseDecision timedOut = new QualityCauseDecision(QualityCauseDecision.SOURCE_MODEL_LESS,
                "TECHNICAL_FALLBACK", null, QualityAction.CHALLENGE, false, true, true, false, false, null, List.of(),
                null, null, null);
        assertThat(QualityCauseClassifier.rated(timedOut).check(QualityCause.FORMAT_AND_MODEL).details())
                .contains("reason=NO_ANSWER", "reason=OVER_TIME_LIMIT", "reason=TECHNICAL_FALLBACK");

        QualityCauseResult engine = QualityCauseClassifier.rated(new QualityCauseDecision(
                QualityCauseDecision.SOURCE_ENGINE_CHANGED, "ESCALATE_PROTECTION", QualityAction.ESCALATE,
                QualityAction.CHALLENGE, true, false, false, false, false, "BUSINESS_AWARE", List.of(), RIGHT,
                QualityCauseDecision.SourceTruth.NOT_SEALED, "OVERREACTION"));
        assertThat(engine.cause()).isEqualTo(QualityCause.ENGINE_CHANGED);
        assertThat(engine.check(QualityCause.ENGINE_CHANGED).details()).containsExactly("model=ESCALATE",
                "action=CHALLENGE", "cause=ESCALATE_PROTECTION");

        QualityCauseResult judged = QualityCauseClassifier.rated(modelDecision(RIGHT));
        assertThat(judged.cause()).isEqualTo(QualityCause.JUDGEMENT_ERROR);
        assertThat(judged.check(QualityCause.JUDGEMENT_ERROR).details()).containsExactly("action=ALLOW",
                "reason=MISSED_SIGNAL");

        // A record written before the decision source and the citations were kept: nothing can be computed.
        QualityCauseResult old = QualityCauseClassifier.rated(new QualityCauseDecision(null, null, null,
                QualityAction.ALLOW, null, false, false, false, false, null, List.of(), null, null, null));
        assertThat(old.cause()).isEqualTo(QualityCause.UNCLASSIFIED);
        assertThat(old.checks()).extracting(QualityCauseCheck::state).containsExactly(NOT_COMPUTED, NOT_COMPUTED,
                NOT_COMPUTED, NOT_COMPUTED, NOT_COMPUTED, NOT_COMPUTED, NOT_COMPUTED);
    }

    // ----- the real measurement -----

    /**
     * The measurement of version v1.0 on the default set, 70 cases once, on the local model (the result kept with
     * the columns the classification reads, no prompt or answer text): 14 answers are wrong, all on both bases.
     */
    @Test
    void theRealMeasurementOfTheDefaultSetIsPutDownToItsCauses() throws IOException {
        Map<String, QualityCase> cases = new HashMap<>();
        QualityCaseSetReader.contexaDefault().cases().forEach(item -> cases.put(item.key(), item));
        List<QualityCauseAnswer> answers = realAnswers();
        assertThat(answers).hasSize(70);
        Map<QualityCause, Integer> counts = new EnumMap<>(QualityCause.class);
        Map<QualityCause, Integer> notComputed = new EnumMap<>(QualityCause.class);
        Map<String, QualityCause> byCase = new HashMap<>();
        int wrong = 0;
        for (QualityCauseAnswer answer : answers) {
            QualityCase item = cases.get(answer.caseKey());
            assertThat(item).as("case %s", answer.caseKey()).isNotNull();
            if (QualityCauseClassifier.wrongOn(item, answer).isEmpty()) {
                continue;
            }
            wrong++;
            QualityCauseResult result = QualityCauseClassifier.measured(item, answer, List.of(answer), LIMIT);
            assertThat(result.basis()).isEqualTo(QualityCauseBasis.BOTH);
            counts.merge(result.cause(), 1, Integer::sum);
            byCase.put(answer.caseKey(), result.cause());
            result.checks().stream().filter(check -> check.state() == NOT_COMPUTED)
                    .forEach(check -> notComputed.merge(check.cause(), 1, Integer::sum));
            if (result.cause() == QualityCause.GROUNDING_ERROR) {
                assertThat(result.check(QualityCause.GROUNDING_ERROR).reason())
                        .isEqualTo(QualityCauseClassifier.CITATION_DOES_NOT_SAY_IT);
            }
        }
        assertThat(wrong).isEqualTo(14);
        assertThat(counts).containsExactlyInAnyOrderEntriesOf(Map.of(QualityCause.GROUNDING_ERROR, 8,
                QualityCause.JUDGEMENT_ERROR, 5, QualityCause.INPUT_SHORTAGE, 1));
        // One run: never unstable; three wrong answers are of original cases, which list no deciding fact.
        assertThat(notComputed).containsExactlyInAnyOrderEntriesOf(Map.of(QualityCause.UNSTABLE, 14,
                QualityCause.INPUT_SHORTAGE, 3));
        // The insider variant lists the on-call record as deciding, and its prompt names it unknown.
        assertThat(byCase.get("INS-S03")).isEqualTo(QualityCause.INPUT_SHORTAGE);
    }

    private static List<QualityCauseAnswer> realAnswers() throws IOException {
        String resource = "prompt-quality/measured-answers/m3ba-v1.0-70x1.jsonl";
        List<QualityCauseAnswer> answers = new ArrayList<>();
        try (InputStream input = QualityCauseClassifierTest.class.getClassLoader().getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                if (line.isBlank()) {
                    continue;
                }
                JsonNode row = QualityFixtures.JSON.readTree(line);
                JsonNode check = row.path("citationCheck");
                List<QualityCauseCitations.Finding> findings = new ArrayList<>();
                check.path("findings").forEach(finding -> findings.add(new QualityCauseCitations.Finding(
                        finding.path("code").asText(), finding.path("fact").asText(), finding.path("outcome").asText(),
                        finding.path("present").asBoolean())));
                List<Long> calls = new ArrayList<>();
                row.path("callMs").forEach(took -> calls.add(took.isNumber() ? took.asLong() : null));
                answers.add(new QualityCauseAnswer(row.path("case").asText(), row.path("run").asInt(),
                        QualityAction.parse(row.path("firstAction").asText(null)),
                        QualityAction.parse(row.path("modelAction").asText(null)),
                        QualityAction.parse(row.path("finalAction").asText(null)),
                        row.path("decidedWithoutModel").asBoolean(),
                        "MODEL_ANSWER_UNUSABLE".equals(row.path("secondPassOutcome").asText(null)),
                        new QualityCauseCitations("CHECKED".equals(check.path("state").asText()),
                                check.path("cited").asInt(), check.path("present").asInt(),
                                check.path("flagged").asInt(), findings),
                        calls, row.path("decisionMillis").isNumber() ? row.path("decisionMillis").asLong() : null,
                        row.path("measurementFailed").asBoolean()));
            }
        }
        return answers;
    }

    @Test
    void theFixOfEachCauseIsTheOneThePlanNames() {
        Map<QualityCause, QualityCauseFix> fixes = new EnumMap<>(QualityCause.class);
        QualityCause.RULED.forEach(cause -> fixes.put(cause, cause.fix()));
        assertThat(fixes).containsExactlyInAnyOrderEntriesOf(Map.of(
                QualityCause.INPUT_SHORTAGE, QualityCauseFix.INTEGRATION,
                QualityCause.GROUNDING_ERROR, QualityCauseFix.PROMPT_OR_MODEL,
                QualityCause.JUDGEMENT_ERROR, QualityCauseFix.PROMPT_VERSION,
                QualityCause.FORMAT_AND_MODEL, QualityCauseFix.MODEL_SETTING,
                QualityCause.UNSTABLE, QualityCauseFix.PROMPT_OR_MODEL,
                QualityCause.ENGINE_CHANGED, QualityCauseFix.RULE_SETTING,
                QualityCause.INPUT_ERROR, QualityCauseFix.COLLECTOR_OR_RECORDS));
        assertThat(QualityCause.UNCLASSIFIED.fix()).isNull();
        assertThat(EnumSet.allOf(QualityCause.class).stream().filter(QualityCause::decisionsOnly).toList())
                .containsExactly(QualityCause.INPUT_ERROR);
        assertThat(QualityCause.parse(" judgement_error ")).isEqualTo(QualityCause.JUDGEMENT_ERROR);
        assertThat(QualityCause.parse("nothing")).isNull();
    }
}
