package io.contexa.showcase.portal.benchmark;

import io.contexa.showcase.portal.benchmark.BenchmarkView.CaseRow;
import io.contexa.showcase.portal.benchmark.BenchmarkView.Cell;
import io.contexa.showcase.portal.benchmark.BenchmarkView.Conclusions;
import io.contexa.showcase.portal.benchmark.BenchmarkView.ControlScore;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * S10: the values the benchmark summary shows that are worked out on the server: the three questions with every tied
 * approach named, the third column (normal work not halted), and the case flags the case list and the limits use.
 */
class BenchmarkSummaryTest {

    private static ControlScore score(String control, long stoppedAny, long attacks, long falseBlocks, long normals,
                                      long checks) {
        return new ControlScore(control, BenchmarkService.rate(0, attacks), BenchmarkService.rate(stoppedAny, attacks),
                null, null, BenchmarkService.rate(falseBlocks, normals), BenchmarkService.rate(checks, normals), null,
                0, 0, 0);
    }

    private static CaseRow row(String classification, long runs, Map<String, Long> contexa, Cell cell) {
        return row("X", classification, runs, contexa, cell);
    }

    private static CaseRow row(String key, String classification, long runs, Map<String, Long> contexa, Cell cell) {
        return new CaseRow(key, classification, Map.of("ko", "x", "en", "x"), runs, List.of(), Map.of("D", contexa),
                Map.of(), Map.of(), Map.of(), List.of(), null, cell == null ? Map.of() : Map.of("D", cell));
    }

    @Test
    void theQuestionsNameEveryTiedApproachAndOnlyTheCleanOnesForTheThird() {
        Conclusions conclusions = Conclusions.of(List.of(
                score("A", 3, 51, 0, 36, 0),
                score("C1", 36, 51, 18, 36, 0),
                score("C2", 39, 51, 0, 36, 0),
                score("D", 39, 51, 0, 36, 6)));

        assertThat(conclusions.mostStopped().controls()).containsExactly("C2", "D");
        assertThat(conclusions.mostStopped().hits()).isEqualTo(39);
        assertThat(conclusions.mostStopped().total()).isEqualTo(51);
        assertThat(conclusions.mostFalseBlock().controls()).containsExactly("C1");
        assertThat(conclusions.mostFalseBlock().hits()).isEqualTo(18);
        assertThat(conclusions.cleanMostStopped().controls()).containsExactly("C2", "D");
    }

    @Test
    void noApproachIsNamedWhenTheHighestCountIsZero() {
        Conclusions conclusions = Conclusions.of(List.of(score("A", 0, 10, 0, 5, 0), score("D", 0, 10, 0, 5, 0)));

        assertThat(conclusions.mostStopped().controls()).isEmpty();
        assertThat(conclusions.mostFalseBlock().controls()).isEmpty();
        assertThat(conclusions.mostFalseBlock().hits()).isZero();
    }

    @Test
    void normalWorkNotHaltedCountsPassesWithAndWithoutACheck() {
        ControlScore contexa = score("D", 39, 51, 0, 36, 6);
        ControlScore threshold = score("C1", 36, 51, 18, 36, 0);

        assertThat(contexa.notBlocked().hits()).isEqualTo(36);
        assertThat(contexa.notBlocked().total()).isEqualTo(36);
        assertThat(threshold.notBlocked().hits()).isEqualTo(18);
        assertThat(threshold.notBlocked().low()).isNotNull();
    }

    @Test
    void aCaseIsWrongWhenOneScoredRunIsAndMissedOnlyWhenEveryRunLetTheAttackThrough() {
        assertThat(row("THREAT", 3, Map.of("MISSED", 3L), new Cell(0, 3)).missedEveryRun()).isTrue();
        assertThat(row("THREAT", 3, Map.of("MISSED", 2L, "STOPPED", 1L), new Cell(1, 3)).missedEveryRun()).isFalse();
        assertThat(row("THREAT", 3, Map.of("PARTLY_STOPPED", 3L), new Cell(0, 3)).missedEveryRun()).isFalse();
        assertThat(row("NORMAL", 3, Map.of("MISSED", 3L), new Cell(3, 3)).missedEveryRun()).isFalse();

        assertThat(row("THREAT", 3, Map.of(), new Cell(1, 3)).contexaWrong()).isTrue();
        assertThat(row("NORMAL", 3, Map.of(), new Cell(3, 3)).contexaWrong()).isFalse();
        assertThat(row("UNCERTAIN", 3, Map.of(), null).contexaWrong()).isFalse();
    }

    @Test
    void theCaseListCountsByClassificationAndTheLimitsListTheCasesMissedEveryTime() {
        BenchmarkView view = new BenchmarkView(Instant.EPOCH, List.of(), List.of(), null, null, List.of(),
                List.of(row("A1", "THREAT", 3, Map.of("MISSED", 3L), new Cell(0, 3)),
                        row("S10", "THREAT", 3, Map.of("MISSED", 2L, "STOPPED", 1L), new Cell(1, 3)),
                        row("A3", "THREAT", 3, Map.of("STOPPED", 3L), new Cell(3, 3)),
                        row("A3T", "NORMAL", 3, Map.of("PASSED", 3L), new Cell(3, 3)),
                        row("S07", "UNCERTAIN", 3, Map.of("NOT_SCORED", 3L), null)),
                List.of(), 0, List.of(), null, Map.of(), null, null, 0);

        assertThat(view.caseCounts()).containsExactly(Map.entry("THREAT", 3L), Map.entry("NORMAL", 1L),
                Map.entry("UNCERTAIN", 1L));
        assertThat(view.contexaWrongCases()).containsExactly(Map.entry("THREAT", 2L), Map.entry("NORMAL", 0L),
                Map.entry("UNCERTAIN", 0L));
        assertThat(view.missedEveryRunCases()).containsExactly("A1");
    }
}
