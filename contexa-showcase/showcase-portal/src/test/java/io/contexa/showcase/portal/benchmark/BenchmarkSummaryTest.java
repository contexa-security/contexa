package io.contexa.showcase.portal.benchmark;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.benchmark.BenchmarkView.CaseRow;
import io.contexa.showcase.portal.benchmark.BenchmarkView.Cell;
import io.contexa.showcase.portal.benchmark.BenchmarkView.Conclusions;
import io.contexa.showcase.portal.benchmark.BenchmarkView.ControlScore;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

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
                Map.of(), Map.of(), Map.of(), List.of(), null, cell == null ? Map.of() : Map.of("D", cell), Map.of());
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

    /**
     * PB-1 and PB-2 of 4.8 (G1 to G3): from each run's own results, the attack runs every existing approach let through
     * with Contexa's results in them, and the rule-blind normal runs every existing approach let pass.
     */
    @Test
    void theBlindSpotCountsTheRunsEveryExistingApproachLetThroughWithWhatContexaDidInThem() {
        Map<String, String> allMissed = Map.of("A", "MISSED", "B", "MISSED", "C1", "MISSED", "C2", "MISSED");
        Map<String, String> ruleStopped = Map.of("A", "MISSED", "B", "MISSED", "C1", "STOPPED", "C2", "MISSED");
        Map<String, String> allPassed = Map.of("A", "PASSED", "B", "PASSED", "C1", "PASSED", "C2", "PASSED");
        CaseRow s13 = withRuns("S13", "THREAT", Map.of(
                "r1", with(allMissed, "STOPPED"), "r2", with(allMissed, "MISSED"), "r3", with(ruleStopped, "STOPPED")));
        CaseRow a3 = withRuns("A3", "THREAT", Map.of("r4", with(ruleStopped, "STOPPED")));
        CaseRow s13t = withRuns("S13T", "NORMAL", Map.of(
                "r5", with(allPassed, "PASSED"), "r6", with(allPassed, "HALTED")));
        CaseRow a3t = withRuns("A3T", "NORMAL", Map.of("r7", with(allPassed, "PASSED")));
        BenchmarkView view = new BenchmarkView(Instant.EPOCH, List.of(), List.of(), null, null, List.of(),
                List.of(a3, a3t, s13, s13t), List.of(), 0,
                List.of(new BenchmarkView.Suite("RULE_BLIND", List.of("S13", "S13T"), 5, List.of())), null,
                Map.of(), Map.of(), List.of(), null, null, 0);

        assertThat(view.blindSpot().attacks()).as("an attack a rule stopped in every run is left out").singleElement()
                .isEqualTo(new BenchmarkView.BlindSpotCase("S13", 3, 2, Map.of("MISSED", 1L, "STOPPED", 1L),
                        List.of(new BenchmarkView.BlindSpotRun("r1", "STOPPED"),
                                new BenchmarkView.BlindSpotRun("r2", "MISSED"))));
        assertThat(view.blindSpot().normals()).as("normal work of the rule-blind suite only").singleElement()
                .isEqualTo(new BenchmarkView.BlindSpotCase("S13T", 2, 2, Map.of("HALTED", 1L, "PASSED", 1L),
                        List.of(new BenchmarkView.BlindSpotRun("r5", "PASSED"),
                                new BenchmarkView.BlindSpotRun("r6", "HALTED"))));
        // BM-S2: the designed pairs (4.6 of the v21 plan) whose attack was measured, and G1 to G3 over them: three
        // attack runs, two let through by all four, Contexa stopped one of those (from the start); two normal runs,
        // both let pass by all four, Contexa let one pass.
        assertThat(view.blindSpot().pairs()).containsExactly(new BenchmarkView.BlindSpotPair("STOLEN_ACCOUNT", "S13", "S13T"));
        assertThat(view.blindSpot().totals()).isEqualTo(new BenchmarkView.BlindSpotTotals(3, 2, 1, 1, 2, 2, 1));
    }

    /**
     * V-64 of docs/showcase/영상전-검토.md: the insider pairs S16 and S18 share the normal work S16T, which the totals count
     * once; the proof names the shared normal work so the screen can say why five pairs hold four normal runs.
     */
    @Test
    void theProofNamesTheNormalWorkTwoPairsShare() {
        Map<String, String> allMissed = Map.of("A", "MISSED", "B", "MISSED", "C1", "MISSED", "C2", "MISSED");
        Map<String, String> allPassed = Map.of("A", "PASSED", "B", "PASSED", "C1", "PASSED", "C2", "PASSED");
        CaseRow s13 = withRuns("S13", "THREAT", Map.of("r1", with(allMissed, "STOPPED")));
        CaseRow s13t = withRuns("S13T", "NORMAL", Map.of("r2", with(allPassed, "PASSED")));
        CaseRow s16 = withRuns("S16", "THREAT", Map.of("r3", with(allMissed, "PARTLY_STOPPED")));
        CaseRow s18 = withRuns("S18", "THREAT", Map.of("r4", with(allMissed, "PARTLY_STOPPED")));
        CaseRow s16t = withRuns("S16T", "NORMAL", Map.of("r5", with(allPassed, "PASSED")));
        BenchmarkView view = new BenchmarkView(Instant.EPOCH, List.of(), List.of(), null, null, List.of(),
                List.of(s13, s13t, s16, s16t, s18), List.of(), 0,
                List.of(new BenchmarkView.Suite("RULE_BLIND", List.of("S13", "S13T", "S16", "S16T", "S18"), 5,
                        List.of())), null, Map.of(), Map.of(), List.of(), null, null, 0);

        assertThat(view.blindSpot().pairs()).extracting(BenchmarkView.BlindSpotPair::normal)
                .containsExactly("S13T", "S16T", "S16T");
        assertThat(view.blindSpot().sharedNormals()).containsExactly("S16T");
        assertThat(view.blindSpot().totals().normalRuns()).as("S16T counted once").isEqualTo(2);
    }

    /**
     * BM-S2: every case a designed pair names is a case of the catalog, an attack's pair is normal work, and the insider
     * group holds exactly the attacks the account's owner carries out.
     */
    @Test
    void theDesignedPairsNameCasesOfTheCatalog() throws IOException {
        ScenarioCatalog catalog = new ScenarioCatalog(new ObjectMapper().findAndRegisterModules());
        for (BenchmarkView.BlindSpotPair pair : BenchmarkView.PAIRS) {
            assertThat(catalog.find(pair.attack())).as(pair.attack()).get()
                    .satisfies(found -> assertThat(found.oracle().classification()).isEqualTo("THREAT"))
                    .satisfies(found -> assertThat(ScenarioDefinition.Oracle.OWNER_ACTS.equals(found.oracle().actor()))
                            .as(pair.attack() + " in " + pair.group()).isEqualTo("INSIDER".equals(pair.group())));
            assertThat(catalog.find(pair.normal())).as(pair.normal()).get()
                    .satisfies(found -> assertThat(found.oracle().classification()).isEqualTo("NORMAL"));
        }
    }

    private static Map<String, String> with(Map<String, String> existing, String contexa) {
        Map<String, String> results = new HashMap<>(existing);
        results.put("D", contexa);
        return results;
    }

    private static CaseRow withRuns(String key, String classification, Map<String, Map<String, String>> runResults) {
        return new CaseRow(key, classification, Map.of("ko", "x", "en", "x"), runResults.size(), List.of(), Map.of(),
                Map.of(), Map.of(), Map.of(), List.of(), null, Map.of(), new TreeMap<>(runResults));
    }

    @Test
    void theCaseListCountsByClassificationAndTheLimitsListTheCasesMissedEveryTime() {
        BenchmarkView view = new BenchmarkView(Instant.EPOCH, List.of(), List.of(), null, null, List.of(),
                List.of(row("A1", "THREAT", 3, Map.of("MISSED", 3L), new Cell(0, 3)),
                        row("S10", "THREAT", 3, Map.of("MISSED", 2L, "STOPPED", 1L), new Cell(1, 3)),
                        row("A3", "THREAT", 3, Map.of("STOPPED", 3L), new Cell(3, 3)),
                        row("A3T", "NORMAL", 3, Map.of("PASSED", 3L), new Cell(3, 3)),
                        row("S07", "UNCERTAIN", 3, Map.of("NOT_SCORED", 3L), null)),
                List.of(), 0, List.of(), null, Map.of(), Map.of(), List.of(), null, null, 0);

        assertThat(view.caseCounts()).containsExactly(Map.entry("THREAT", 3L), Map.entry("NORMAL", 1L),
                Map.entry("UNCERTAIN", 1L));
        assertThat(view.contexaWrongCases()).containsExactly(Map.entry("THREAT", 2L), Map.entry("NORMAL", 0L),
                Map.entry("UNCERTAIN", 0L));
        assertThat(view.missedEveryRunCases()).containsExactly("A1");
    }
}
