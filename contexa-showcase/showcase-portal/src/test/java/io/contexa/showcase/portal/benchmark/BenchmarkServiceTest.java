package io.contexa.showcase.portal.benchmark;

import io.contexa.showcase.portal.scoring.RunScores.RunScore;
import io.contexa.showcase.portal.scoring.RunScores.TruthSource;
import io.contexa.showcase.portal.scoring.Scoring.BusinessResult;
import io.contexa.showcase.portal.scoring.Scoring.CaseScore;
import io.contexa.showcase.portal.scoring.Scoring.Truth;
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
