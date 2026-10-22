package io.contexa.showcase.portal.benchmark;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

/**
 * W5-1: the scorecard of one approach, counted from scored protocol runs by the one scoring rule. Unresolved runs leave
 * the denominator; a partial stop counts as a stop in "stopped at some step" only; every rate carries its Wilson 95%
 * interval; the per-case mean weighs each case once (R-14).
 */
class BenchmarkServiceTest {

    private static final Truth THREAT = new Truth("THREAT", List.of("BLOCK", "CHALLENGE", "ESCALATE"));
    private static final Truth NORMAL = new Truth("NORMAL", List.of("ALLOW", "CHALLENGE"));

    private static RunScore run(String id, String key, Truth truth, BusinessResult result, long exposed) {
        return new RunScore(id, key, 1, "COMPLETED", TruthSource.RUN_SNAPSHOT, truth, 1, 1,
                Map.of("D", new CaseScore(result, exposed, 1)), Map.of(), List.of(), List.of(), null);
    }

    @Test
    void anApproachIsScoredOverResolvedRunsWithWilsonIntervalsAndPerCaseMeans() {
        List<RunScore> runs = List.of(
                run("r1", "A3", THREAT, BusinessResult.STOPPED, 0),
                run("r2", "A3", THREAT, BusinessResult.STOPPED, 0),
                run("r3", "A6", THREAT, BusinessResult.PARTLY_STOPPED, 1),
                run("r4", "A6", THREAT, BusinessResult.MISSED, 5),
                run("r5", "A1", THREAT, BusinessResult.UNRESOLVED, 0),
                run("r6", "A3T", NORMAL, BusinessResult.PASSED, 0),
                run("r7", "A3T", NORMAL, BusinessResult.PASSED_AFTER_CHECK, 0),
                run("r8", "S02", NORMAL, BusinessResult.HALTED, 0));

        BenchmarkView.ControlScore d = BenchmarkService.controls(runs).stream()
                .filter(score -> score.control().equals("D")).findFirst().orElseThrow();

        assertThat(d.attackUnresolved()).isEqualTo(1);
        assertThat(d.stopped().hits()).isEqualTo(2);
        assertThat(d.stopped().total()).as("the unresolved run leaves the denominator").isEqualTo(4);
        assertThat(d.stoppedAny().hits()).as("a partial stop is a stop at some step").isEqualTo(3);
        assertThat(d.stoppedMacro()).as("A3 1.0 and A6 0.0, each case once").isCloseTo(0.5, within(1e-9));
        assertThat(d.stoppedAnyMacro()).as("A3 1.0 and A6 0.5 (the partial stop counts)").isCloseTo(0.75, within(1e-9));
        assertThat(d.exposedItems()).isEqualTo(6);
        assertThat(d.falseBlock().hits()).isEqualTo(1);
        assertThat(d.falseBlock().total()).isEqualTo(3);
        assertThat(d.friction().hits()).as("passed only after an identity check").isEqualTo(1);
        assertThat(d.falseBlockMacro()).as("A3T 0.0 and S02 1.0").isCloseTo(0.5, within(1e-9));
        // Wilson 95% interval of 2 of 4: 0.150 to 0.850.
        assertThat(d.stopped().low()).isCloseTo(0.1500, within(1e-3));
        assertThat(d.stopped().high()).isCloseTo(0.8500, within(1e-3));
    }

    @Test
    void aRateOfNothingCountedHasNoValueAndNoInterval() {
        BenchmarkView.Rate none = BenchmarkService.rate(0, 0);

        assertThat(none.rate()).isNull();
        assertThat(none.low()).isNull();
        assertThat(BenchmarkService.rate(0, 13).high()).isCloseTo(0.2281, within(1e-3));
    }

    /** The numbers the benchmark screen used to work out by subtraction are the server's (T-27). */
    @Test
    void derivedCountsAreTheServers() {
        BenchmarkView.ControlScore score = new BenchmarkView.ControlScore("D", BenchmarkService.rate(12, 45),
                BenchmarkService.rate(34, 45), null, null, BenchmarkService.rate(0, 30), BenchmarkService.rate(4, 30),
                null, 0, 0, 22637);

        assertThat(score.partlyStopped()).isEqualTo(22);
        assertThat(score.missed()).isEqualTo(11);
        assertThat(score.normalPassed()).isEqualTo(26);
        assertThat(new BenchmarkView.Cell(2, 3).state()).isEqualTo("MIXED");
        assertThat(new BenchmarkView.Cell(0, 0).state()).isEqualTo("NONE");
        assertThat(new BenchmarkView.Cell(3, 3).state()).isEqualTo("RIGHT");
        assertThat(new BenchmarkView.Cell(0, 3).state()).isEqualTo("WRONG");
    }

    private static StepVerdict step(int stepNo, String action, String applied, DecisionSource source,
                                    boolean applicable) {
        VerdictResult result = action == null ? VerdictResult.NO_DECISION : VerdictResult.RIGHT;
        return new StepVerdict(new VerdictScore(stepNo, action, result, applicable, false, applied), source, action);
    }

    private static RunScore attack(String id, String key, BusinessResult result, long exposed, StepVerdict... steps) {
        return new RunScore(id, key, 1, "COMPLETED", TruthSource.RUN_SNAPSHOT, THREAT, steps.length, steps.length,
                Map.of("D", new CaseScore(result, exposed, 1)), Map.of(), List.of(steps), List.of(), null);
    }

    /** The shapes of the 2026-10-20 measurement protocol-7b925e8e (v21.8), one run of each kind and both "other" runs. */
    private static List<RunScore> measuredShapes() {
        return List.of(
                // R1 run-8ddb21acf432: refused by the role check before any analysis.
                attack("run-r1", "R1", BusinessResult.STOPPED, 0,
                        step(1, null, "NONE", DecisionSource.STATIC_AUTHORIZATION, false)),
                // A3: the export held for a CHALLENGE before any item left.
                attack("run-a3", "A3", BusinessResult.STOPPED, 0,
                        step(1, "CHALLENGE", "BEFORE_RESPONSE", DecisionSource.MODEL, true)),
                // A3S: the stream left, the CHALLENGE applied from the next request refused what followed.
                attack("run-a3s", "A3S", BusinessResult.PARTLY_STOPPED, 4831,
                        step(1, "CHALLENGE", "NEXT_REQUEST", DecisionSource.MODEL, true),
                        step(2, null, "NONE", DecisionSource.PRIOR_DECISION, false)),
                // S17 run-3bb57a898289: allowed, the 300 items left.
                attack("run-s17", "S17", BusinessResult.MISSED, 300,
                        step(1, "ALLOW", "BEFORE_RESPONSE", DecisionSource.MODEL, true)),
                // S11 run-87c7bd071cb8: request 1 allowed before the response, request 2 blocked before the response,
                // the rest refused by that decision.
                attack("run-s11", "S11", BusinessResult.PARTLY_STOPPED, 480,
                        step(1, "ALLOW", "BEFORE_RESPONSE", DecisionSource.MODEL, true),
                        step(2, "BLOCK", "BEFORE_RESPONSE", DecisionSource.MODEL, true),
                        step(3, null, "NONE", DecisionSource.PRIOR_DECISION, false),
                        step(4, null, "NONE", DecisionSource.PRIOR_DECISION, false)),
                // S19 run-8d9e43b2882e: document 1 allowed, document 2 not analysed, document 3 met a CHALLENGE that
                // applied from a next request there was none of: all three left.
                attack("run-s19", "S19", BusinessResult.MISSED, 3,
                        step(1, "ALLOW", "NEXT_REQUEST", DecisionSource.MODEL, true),
                        step(2, null, "NONE", DecisionSource.NOT_ANALYSED, false),
                        step(3, "CHALLENGE", "NEXT_REQUEST", DecisionSource.MODEL, false)),
                run("run-n1", "A3T", NORMAL, BusinessResult.PASSED, 0));
    }

    /**
     * V-01 of docs/showcase/영상전-검토.md: the line "of the n attacks judged risky, m were stopped" names which bars the
     * risky runs sit in and which risky run was not stopped, so it adds up with the bar.
     */
    @Test
    void theRiskyRunsAreCountedByTheirKindAndTheOneNotStoppedIsNamed() {
        BenchmarkView.RiskJudged risky = BenchmarkService.riskJudged(measuredShapes());

        assertThat(risky.runs()).as("A3, A3S, S11 and S19 made a decision not to allow").isEqualTo(4);
        assertThat(risky.stopped()).isEqualTo(3);
        assertThat(risky.kinds()).containsExactly(Map.entry("STATIC_REFUSAL", 0L), Map.entry("BEFORE_RESPONSE", 1L),
                Map.entry("NEXT_REQUEST", 1L), Map.entry("JUDGED_ALLOW", 0L), Map.entry("OTHER", 2L));
        assertThat(risky.notStopped()).containsExactly("S19");
    }

    /** V-01: the runs of the kind "other", each with its case, its result and the shape of every step. */
    @Test
    void theOtherRunsCarryTheirCaseResultAndTheShapeOfEveryStep() {
        List<BenchmarkView.JudgmentRun> others = BenchmarkService.judgmentOthers(measuredShapes());

        assertThat(others).extracting(BenchmarkView.JudgmentRun::caseKey).containsExactly("S11", "S19");
        BenchmarkView.JudgmentRun s11 = others.get(0);
        assertThat(s11.runId()).isEqualTo("run-s11");
        assertThat(s11.result()).isEqualTo("PARTLY_STOPPED");
        assertThat(s11.exposedItems()).isEqualTo(480);
        assertThat(s11.steps()).containsExactly(
                new BenchmarkView.JudgmentStep(1, "ALLOW", "BEFORE_RESPONSE", "MODEL", true),
                new BenchmarkView.JudgmentStep(2, "BLOCK", "BEFORE_RESPONSE", "MODEL", true),
                new BenchmarkView.JudgmentStep(3, null, "NONE", "PRIOR_DECISION", false),
                new BenchmarkView.JudgmentStep(4, null, "NONE", "PRIOR_DECISION", false));
        BenchmarkView.JudgmentRun s19 = others.get(1);
        assertThat(s19.result()).isEqualTo("MISSED");
        assertThat(s19.exposedItems()).isEqualTo(3);
        assertThat(s19.steps()).containsExactly(
                new BenchmarkView.JudgmentStep(1, "ALLOW", "NEXT_REQUEST", "MODEL", true),
                new BenchmarkView.JudgmentStep(2, null, "NONE", "NOT_ANALYSED", false),
                new BenchmarkView.JudgmentStep(3, "CHALLENGE", "NEXT_REQUEST", "MODEL", false));
    }

    /**
     * Decision 6 of docs/showcase/화면설계서-v2-구현계획.md: Contexa's wrong runs are the attacks it let through and the
     * normal tasks it stopped; a run stopped after some items left counts as stopped, an unresolved one apart.
     */
    @Test
    void onlyAMissedAttackAndAHaltedTaskAreListedAsWrong() {
        assertThat(BenchmarkService.listedAsWrong(BusinessResult.MISSED)).isTrue();
        assertThat(BenchmarkService.listedAsWrong(BusinessResult.HALTED)).isTrue();
        assertThat(BenchmarkService.listedAsWrong(BusinessResult.PARTLY_STOPPED)).isFalse();
        assertThat(BenchmarkService.listedAsWrong(BusinessResult.UNRESOLVED)).isFalse();
        assertThat(BenchmarkService.listedAsWrong(BusinessResult.STOPPED)).isFalse();
    }
}
