package io.contexa.showcase.portal.scoring;

import io.contexa.showcase.portal.scoring.Scoring.BusinessResult;
import io.contexa.showcase.portal.scoring.Scoring.CaseScore;
import io.contexa.showcase.portal.scoring.Scoring.StepAnswer;
import io.contexa.showcase.portal.scoring.Scoring.StepDecision;
import io.contexa.showcase.portal.scoring.Scoring.Truth;
import io.contexa.showcase.portal.scoring.Scoring.VerdictResult;
import io.contexa.showcase.portal.scoring.Scoring.VerdictScore;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The truth table of the one scoring rule (docs/showcase/데모-재설계.md 5.0, V-12): every combination of ground truth,
 * business outcome, decision source and chance to apply has a fixed answer.
 */
class ScoringTest {

    private static final Truth THREAT = new Truth("THREAT", List.of("BLOCK", "CHALLENGE", "ESCALATE"));
    private static final Truth NORMAL = new Truth("NORMAL", List.of("ALLOW", "CHALLENGE"));
    private static final Truth UNCERTAIN = new Truth("UNCERTAIN", List.of("ALLOW", "CHALLENGE", "ESCALATE"));

    private static StepAnswer answer(int step, String outcome, long items) {
        return new StepAnswer(step, outcome, null, items, null);
    }

    private static StepAnswer checked(int step, boolean passed) {
        return new StepAnswer(step, "REFUSED", 401, 0, passed);
    }

    @Test
    void anAttackIsStoppedOnlyWhenNoDataLeftAtAnyStep() {
        assertThat(Scoring.business(THREAT, List.of(answer(1, "REFUSED", 0), answer(2, "REFUSED", 0))))
                .isEqualTo(new CaseScore(BusinessResult.STOPPED, 0, null));
        assertThat(Scoring.business(THREAT, List.of(answer(1, "CUT", 0))).result())
                .as("a stream cut before the first line").isEqualTo(BusinessResult.STOPPED);
    }

    @Test
    void anAttackThatLeftDataBeforeBeingStoppedIsPartlyStoppedWithItsExposure() {
        CaseScore cut = Scoring.business(THREAT, List.of(answer(1, "CUT", 4000)));
        assertThat(cut).as("4,000 items left before the cut: a partial stop with its exposure, never a clean stop (R-09)")
                .isEqualTo(new CaseScore(BusinessResult.PARTLY_STOPPED, 4000, 1));

        CaseScore laterStop = Scoring.business(THREAT, List.of(answer(1, "DELIVERED", 1), answer(2, "REFUSED", 0)));
        assertThat(laterStop).isEqualTo(new CaseScore(BusinessResult.PARTLY_STOPPED, 1, 1));

        CaseScore cutThenStopped = Scoring.business(THREAT, List.of(answer(1, "CUT", 312), answer(2, "REFUSED", 0)));
        assertThat(cutThenStopped).isEqualTo(new CaseScore(BusinessResult.PARTLY_STOPPED, 312, 1));
    }

    @Test
    void anAttackThatLeftDataAtEveryStepIsMissed() {
        assertThat(Scoring.business(THREAT, List.of(answer(1, "DELIVERED", 1), answer(2, "DELIVERED", 1))))
                .isEqualTo(new CaseScore(BusinessResult.MISSED, 2, 1));
    }

    @Test
    void legitimateWorkPassesDirectlyOrAfterAnAnsweredCheckAndIsHaltedOtherwise() {
        assertThat(Scoring.business(NORMAL, List.of(answer(1, "DELIVERED", 4831))).result())
                .isEqualTo(BusinessResult.PASSED);
        assertThat(Scoring.business(NORMAL, List.of(checked(1, true))).result())
                .as("the check was answered and the re-issued request delivered").isEqualTo(BusinessResult.PASSED_AFTER_CHECK);
        assertThat(Scoring.business(NORMAL, List.of(checked(1, false))))
                .as("a check left unanswered halts the work").isEqualTo(new CaseScore(BusinessResult.HALTED, 0, 1));
        assertThat(Scoring.business(NORMAL, List.of(answer(1, "DELIVERED", 1), answer(2, "REFUSED", 0))))
                .isEqualTo(new CaseScore(BusinessResult.HALTED, 1, 2));
        assertThat(Scoring.business(NORMAL, List.of(answer(1, "CUT", 900))).result())
                .as("a cut legitimate stream is a false block").isEqualTo(BusinessResult.HALTED);
    }

    @Test
    void aFailedRequestOrACaseWithoutGroundTruthIsNotScored() {
        assertThat(Scoring.business(THREAT, List.of(answer(1, "ERROR", 0))).result())
                .isEqualTo(BusinessResult.UNRESOLVED);
        assertThat(Scoring.business(NORMAL, List.of()).result()).isEqualTo(BusinessResult.UNRESOLVED);
        assertThat(Scoring.business(UNCERTAIN, List.of(answer(1, "DELIVERED", 2))))
                .isEqualTo(new CaseScore(BusinessResult.NOT_SCORED, 2, null));
    }

    @Test
    void aStreamThatBrokeAfterItsLinesLeftCountsTheDataThatLeft() {
        // Recorded 2026-10-06: after a CHALLENGE, control D's stream sent all 4,831 lines and then broke.
        assertThat(Scoring.business(THREAT, List.of(answer(1, "ERROR", 4831))))
                .as("the error does not hide the exposure").isEqualTo(new CaseScore(BusinessResult.MISSED, 4831, 1));
        assertThat(Scoring.business(THREAT, List.of(answer(1, "ERROR", 4831), answer(2, "REFUSED", 0))))
                .isEqualTo(new CaseScore(BusinessResult.PARTLY_STOPPED, 4831, 1));
        assertThat(Scoring.business(NORMAL, List.of(answer(1, "ERROR", 4831))))
                .as("legitimate work that ended in an error").isEqualTo(new CaseScore(BusinessResult.HALTED, 4831, 1));
    }

    @Test
    void theEngineVerdictIsScoredOnlyFromItsOwnDecision() {
        List<VerdictScore> threat = Scoring.verdicts(THREAT, List.of(
                new StepDecision(1, "ALLOW", false, "NEXT_REQUEST"),
                new StepDecision(2, "CHALLENGE", false, "NEXT_REQUEST"),
                new StepDecision(3, "CHALLENGE", true, "NEXT_REQUEST"),
                new StepDecision(4, null, false, "NONE")), 4);
        assertThat(threat).extracting(VerdictScore::result).containsExactly(VerdictResult.MISSED, VerdictResult.RIGHT,
                VerdictResult.UNRESOLVED, VerdictResult.NO_DECISION);

        List<VerdictScore> normal = Scoring.verdicts(NORMAL, List.of(
                new StepDecision(1, "ALLOW", false, "BEFORE_RESPONSE"),
                new StepDecision(2, "CHALLENGE", false, "BEFORE_RESPONSE"),
                new StepDecision(3, "BLOCK", false, "BEFORE_RESPONSE")), 3);
        assertThat(normal).extracting(VerdictScore::result).containsExactly(VerdictResult.RIGHT, VerdictResult.RIGHT,
                VerdictResult.FALSE_BLOCK);
        assertThat(normal).extracting(VerdictScore::friction).as("a check on legitimate work is friction (R-08)")
                .containsExactly(false, true, false);

        assertThat(Scoring.verdicts(UNCERTAIN, List.of(new StepDecision(1, "ALLOW", false, "NEXT_REQUEST")), 1))
                .extracting(VerdictScore::result).containsExactly(VerdictResult.NOT_SCORED);
    }

    @Test
    void aDecisionAppliedFromTheNextRequestCannotChangeTheLastStep() {
        List<VerdictScore> scores = Scoring.verdicts(THREAT, List.of(
                new StepDecision(1, "CHALLENGE", false, "NEXT_REQUEST"),
                new StepDecision(2, "CHALLENGE", false, "NEXT_REQUEST")), 2);
        assertThat(scores).extracting(VerdictScore::applicable).as("R-12").containsExactly(true, false);
        assertThat(Scoring.verdicts(THREAT, List.of(new StepDecision(1, "BLOCK", false, "BEFORE_RESPONSE")), 1))
                .extracting(VerdictScore::applicable).containsExactly(true);
    }

    @Test
    void onlyAFullStopAndPassedWorkAreRightAndAPartialStopIsNeither() {
        assertThat(Scoring.correct(BusinessResult.STOPPED)).isTrue();
        assertThat(Scoring.correct(BusinessResult.PASSED)).isTrue();
        assertThat(Scoring.correct(BusinessResult.PASSED_AFTER_CHECK)).isTrue();
        assertThat(Scoring.correct(BusinessResult.MISSED)).isFalse();
        assertThat(Scoring.correct(BusinessResult.HALTED)).isFalse();
        assertThat(Scoring.correct(BusinessResult.PARTLY_STOPPED)).as("shown with its exposure (R-09)").isNull();
        assertThat(Scoring.correct(BusinessResult.UNRESOLVED)).isNull();
        assertThat(Scoring.correct(BusinessResult.NOT_SCORED)).isNull();
    }
}
