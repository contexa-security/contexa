package io.contexa.showcase.portal.scoring;

import io.contexa.showcase.portal.scoring.JudgmentTiming.Kind;
import io.contexa.showcase.portal.scoring.RunScores.DecisionSource;
import io.contexa.showcase.portal.scoring.RunScores.RunScore;
import io.contexa.showcase.portal.scoring.RunScores.StepVerdict;
import io.contexa.showcase.portal.scoring.RunScores.TruthSource;
import io.contexa.showcase.portal.scoring.Scoring.BusinessResult;
import io.contexa.showcase.portal.scoring.Scoring.CaseScore;
import io.contexa.showcase.portal.scoring.Scoring.Truth;
import io.contexa.showcase.portal.scoring.Scoring.VerdictResult;
import io.contexa.showcase.portal.scoring.Scoring.VerdictScore;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The judgement-and-timing kinds of work 16 (docs/showcase/화면설계서-v2-구현계획.md), on the shapes of real runs of
 * the 2026-10-07 measurement protocol-29409667, whose 45 attack runs split 3, 9, 22 and 11.
 */
class JudgmentTimingTest {

    private static final Truth THREAT = new Truth("THREAT", List.of("BLOCK", "CHALLENGE", "ESCALATE"));
    private static final Truth NORMAL = new Truth("NORMAL", List.of("ALLOW", "CHALLENGE"));

    @Test
    void theStaticAuthorizationRefusedBeforeAnyAnalysis() {
        // R1 run-06bad8511848: both requests refused by the role check (403 Forbidden), no engine decision.
        RunScore r1 = run(THREAT, BusinessResult.STOPPED,
                step(1, null, "NONE", DecisionSource.STATIC_AUTHORIZATION),
                step(2, null, "NONE", DecisionSource.STATIC_AUTHORIZATION));

        assertThat(JudgmentTiming.of(r1)).contains(Kind.STATIC_REFUSAL);
    }

    @Test
    void theEngineDecidedBeforeTheResponse() {
        // A3 run-d9e438853e46: the export was held for the engine's CHALLENGE before any item left.
        RunScore a3 = run(THREAT, BusinessResult.STOPPED, step(1, "CHALLENGE", "BEFORE_RESPONSE", DecisionSource.MODEL));

        assertThat(JudgmentTiming.of(a3)).contains(Kind.BEFORE_RESPONSE);
    }

    @Test
    void aDecisionFromTheNextRequestRefusedWhatFollowed() {
        // A3S run-a81f8672e2c2: the stream sent 4,831 items, the CHALLENGE applied from the next request refused it.
        RunScore a3s = run(THREAT, BusinessResult.PARTLY_STOPPED,
                step(1, "CHALLENGE", "NEXT_REQUEST", DecisionSource.MODEL),
                step(2, null, "NONE", DecisionSource.PRIOR_DECISION));

        assertThat(JudgmentTiming.of(a3s)).contains(Kind.NEXT_REQUEST);
        assertThat(JudgmentTiming.judgedRisky(a3s)).isTrue();
    }

    @Test
    void everyDecisionWasToAllow() {
        // S10 run-257422209abc: six downloads, each allowed.
        RunScore s10 = run(THREAT, BusinessResult.MISSED,
                step(1, "ALLOW", "NEXT_REQUEST", DecisionSource.MODEL),
                step(2, "ALLOW", "NEXT_REQUEST", DecisionSource.MODEL));

        assertThat(JudgmentTiming.of(s10)).contains(Kind.JUDGED_ALLOW);
        assertThat(JudgmentTiming.judgedRisky(s10)).isFalse();
    }

    @Test
    void aRefusingDecisionTooLateToActIsNeitherAJudgementToAllowNorTheNextRequest() {
        RunScore late = run(THREAT, BusinessResult.MISSED, step(1, "CHALLENGE", "NEXT_REQUEST", DecisionSource.MODEL));

        assertThat(JudgmentTiming.of(late)).contains(Kind.OTHER);
    }

    @Test
    void onlyAttackRunsWithAResultAreCounted() {
        assertThat(JudgmentTiming.of(run(NORMAL, BusinessResult.PASSED,
                step(1, "ALLOW", "BEFORE_RESPONSE", DecisionSource.MODEL)))).isEqualTo(Optional.empty());
        assertThat(JudgmentTiming.of(run(THREAT, BusinessResult.UNRESOLVED,
                step(1, "ALLOW", "BEFORE_RESPONSE", DecisionSource.FALLBACK)))).isEqualTo(Optional.empty());
    }

    private static StepVerdict step(int stepNo, String finalAction, String applied, DecisionSource source) {
        VerdictResult result = finalAction == null ? VerdictResult.NO_DECISION : VerdictResult.RIGHT;
        return new StepVerdict(new VerdictScore(stepNo, finalAction, result, true, false, applied), source,
                finalAction);
    }

    private static RunScore run(Truth truth, BusinessResult result, StepVerdict... steps) {
        return new RunScore("run-1", "X", 1, "COMPLETED", TruthSource.RUN_SNAPSHOT, truth, steps.length,
                steps.length, Map.of("D", new CaseScore(result, 0, null)), Map.of(), List.of(steps), List.of(),
                null);
    }
}
