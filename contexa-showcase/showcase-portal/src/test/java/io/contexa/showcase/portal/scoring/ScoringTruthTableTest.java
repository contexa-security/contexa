package io.contexa.showcase.portal.scoring;

import io.contexa.showcase.portal.scoring.Scoring.BusinessResult;
import io.contexa.showcase.portal.scoring.Scoring.CaseScore;
import io.contexa.showcase.portal.scoring.Scoring.StepAnswer;
import io.contexa.showcase.portal.scoring.Scoring.StepDecision;
import io.contexa.showcase.portal.scoring.Scoring.Truth;
import io.contexa.showcase.portal.scoring.Scoring.VerdictResult;
import io.contexa.showcase.portal.scoring.Scoring.VerdictScore;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * V-12 (docs/showcase/데모-재설계.md 10.4): every cell of the score rule of 5.0 is pinned. The expected values are copied
 * from the rule as written, not from the code: ground truth x one control's answer for the business axis, ground truth
 * x final action x unresolved for the verdict axis, and when the decision is applied x the step's place for the chance
 * to apply it. The decision source only decides the verdict axis's input (FALLBACK is an unresolved decision;
 * PRIOR_DECISION, STATIC_AUTHORIZATION and NOT_ANALYSED have no decision; MODEL and PROPOSAL_CHANGED are scored on the
 * final action); which source a step has is pinned by RunScoresTest.everyStepWithoutAModelDecisionSaysWhy.
 */
class ScoringTruthTableTest {

    private static Truth truth(String classification) {
        return switch (classification) {
            case "THREAT" -> new Truth("THREAT", List.of("BLOCK", "CHALLENGE", "ESCALATE"));
            case "NORMAL" -> new Truth("NORMAL", List.of("ALLOW", "CHALLENGE"));
            default -> new Truth(classification, List.of("ALLOW", "CHALLENGE", "ESCALATE"));
        };
    }

    @ParameterizedTest(name = "{0} {1} {2} items check {3} -> {4} exposing {5}")
    @CsvSource(nullValues = "-", value = {
            // An attack: stopped only when nothing left; a cut after some lines is a partial stop with its exposure.
            "THREAT,    DELIVERED, 7,    -,     MISSED,             7",
            "THREAT,    CUT,       0,    -,     STOPPED,            0",
            "THREAT,    CUT,       312,  -,     PARTLY_STOPPED,     312",
            "THREAT,    REFUSED,   0,    -,     STOPPED,            0",
            "THREAT,    REFUSED,   0,    true,  STOPPED,            0",
            "THREAT,    NOT_FOUND, 0,    -,     STOPPED,            0",
            "THREAT,    ERROR,     0,    -,     UNRESOLVED,         0",
            "THREAT,    ERROR,     4831, -,     MISSED,             4831",
            // Legitimate work: passed, passed after an answered check, otherwise halted.
            "NORMAL,    DELIVERED, 7,    -,     PASSED,             7",
            "NORMAL,    CUT,       0,    -,     HALTED,             0",
            "NORMAL,    CUT,       312,  -,     HALTED,             312",
            "NORMAL,    REFUSED,   0,    -,     HALTED,             0",
            "NORMAL,    REFUSED,   0,    false, HALTED,             0",
            "NORMAL,    REFUSED,   0,    true,  PASSED_AFTER_CHECK, 0",
            "NORMAL,    NOT_FOUND, 0,    -,     HALTED,             0",
            "NORMAL,    ERROR,     0,    -,     UNRESOLVED,         0",
            "NORMAL,    ERROR,     4831, -,     HALTED,             4831",
            // No ground truth: never scored, the items that left are still shown.
            "UNCERTAIN, DELIVERED, 7,    -,     NOT_SCORED,         7",
            "UNCERTAIN, REFUSED,   0,    -,     NOT_SCORED,         0",
            "UNCERTAIN, ERROR,     0,    -,     NOT_SCORED,         0",
            "NONE,      CUT,       312,  -,     NOT_SCORED,         312",
    })
    void businessAxis(String classification, String outcome, long items, Boolean check, BusinessResult expected,
                      long exposed) {
        CaseScore score = Scoring.business(truth(classification),
                List.of(new StepAnswer(1, outcome, null, items, check)));

        assertThat(score.result()).isEqualTo(expected);
        assertThat(score.exposedItems()).isEqualTo(exposed);
    }

    @ParameterizedTest(name = "{0} without any answer -> {1}")
    @CsvSource({"THREAT, UNRESOLVED", "NORMAL, UNRESOLVED", "UNCERTAIN, NOT_SCORED"})
    void businessAxisWithoutAnswer(String classification, BusinessResult expected) {
        assertThat(Scoring.business(truth(classification), List.of()).result()).isEqualTo(expected);
    }

    @ParameterizedTest(name = "{0} {1} unresolved {2} -> {3} friction {4}")
    @CsvSource({
            "THREAT,    ALLOW,     false, MISSED,      false",
            "THREAT,    CHALLENGE, false, RIGHT,       false",
            "THREAT,    BLOCK,     false, RIGHT,       false",
            "THREAT,    ESCALATE,  false, RIGHT,       false",
            "NORMAL,    ALLOW,     false, RIGHT,       false",
            "NORMAL,    CHALLENGE, false, RIGHT,       true",
            "NORMAL,    BLOCK,     false, FALSE_BLOCK, false",
            "NORMAL,    ESCALATE,  false, FALSE_BLOCK, false",
            "UNCERTAIN, ALLOW,     false, NOT_SCORED,  false",
            "UNCERTAIN, BLOCK,     false, NOT_SCORED,  false",
            "THREAT,    CHALLENGE, true,  UNRESOLVED,  false",
            "NORMAL,    CHALLENGE, true,  UNRESOLVED,  false",
            "UNCERTAIN, CHALLENGE, true,  UNRESOLVED,  false",
    })
    void verdictAxis(String classification, String action, boolean unresolved, VerdictResult expected,
                     boolean friction) {
        VerdictScore score = Scoring.verdicts(truth(classification),
                List.of(new StepDecision(1, action, unresolved, "BEFORE_RESPONSE")), 1).get(0);

        assertThat(score.result()).isEqualTo(expected);
        assertThat(score.friction()).isEqualTo(friction);
    }

    @ParameterizedTest(name = "{0}: no decision -> NO_DECISION")
    @CsvSource({"THREAT", "NORMAL", "UNCERTAIN"})
    void verdictAxisWithoutDecision(String classification) {
        VerdictScore score = Scoring.verdicts(truth(classification),
                List.of(new StepDecision(1, null, false, "NONE")), 2).get(0);

        assertThat(score.result()).isEqualTo(VerdictResult.NO_DECISION);
        assertThat(score.applicable()).isFalse();
    }

    @ParameterizedTest(name = "applied {0} at step {1} of {2} -> chance to apply {3}")
    @CsvSource({
            "BEFORE_RESPONSE, 1, 2, true",
            "BEFORE_RESPONSE, 2, 2, true",
            "NEXT_REQUEST,    1, 2, true",
            "NEXT_REQUEST,    2, 2, false",
            "NONE,            1, 2, false",
    })
    void chanceToApply(String applied, int step, int lastStep, boolean expected) {
        VerdictScore score = Scoring.verdicts(truth("THREAT"),
                List.of(new StepDecision(step, "BLOCK", false, applied)), lastStep).get(0);

        assertThat(score.applicable()).isEqualTo(expected);
    }

    @ParameterizedTest(name = "{0} -> right {1}")
    @CsvSource(nullValues = "-", value = {
            "STOPPED, true", "PASSED, true", "PASSED_AFTER_CHECK, true", "MISSED, false", "HALTED, false",
            "PARTLY_STOPPED, -", "UNRESOLVED, -", "NOT_SCORED, -",
    })
    void rightOrWrong(BusinessResult result, Boolean expected) {
        assertThat(Scoring.correct(result)).isEqualTo(expected);
    }
}
