package io.contexa.showcase.portal.hook;

import io.contexa.showcase.portal.hook.HookStore.RunFacts;
import io.contexa.showcase.portal.hook.HookStore.Slot;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The first screen replays only measured runs an operator designated, and states that the two were told apart only
 * when every measured run says so (work 17 and section 8 of docs/showcase/화면설계서-v2-구현계획.md).
 */
class HookViewsTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private static final Duration KEPT = Duration.ofDays(90);

    private final List<String> designated = new ArrayList<>();
    private final Map<String, RunFacts> runs = Map.of(
            "run-a", facts("run-a", "A3", "COMPLETED", null, "p-1", NOW.minus(Duration.ofDays(1))),
            "run-o", facts("run-o", "A3T", "COMPLETED", null, "p-1", NOW.minus(Duration.ofDays(1))),
            "run-other", facts("run-other", "A3T", "COMPLETED", null, "p-2", NOW.minus(Duration.ofDays(1))),
            "run-forced", facts("run-forced", "A3", "COMPLETED", "CHALLENGE", "p-1", NOW.minus(Duration.ofDays(1))),
            "run-live", facts("run-live", "A3", "COMPLETED", null, null, NOW.minus(Duration.ofDays(1))),
            "run-old", facts("run-old", "A3", "COMPLETED", null, "p-1", NOW.minus(Duration.ofDays(91))));

    private final HookStore store = new HookStore(null) {
        @Override
        public Optional<RunFacts> facts(String runId) {
            return Optional.ofNullable(runs.get(runId));
        }

        @Override
        public void designate(Slot slot, String runId, Instant at) {
            designated.add(slot + "=" + runId);
        }
    };

    private final HookViews hook = new HookViews(store, null, null, KEPT, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void twoMeasuredRunsOfTheSameMeasurementAreDesignatedTogether() {
        assertThat(hook.designate("run-a", "run-o")).isEmpty();
        assertThat(designated).containsExactly("ATTACKER=run-a", "OWNER=run-o");
    }

    @Test
    void aRunThatIsNotAKeptMeasuredRunOfTheSlotsCaseIsRefused() {
        assertThat(hook.designate("run-o", "run-o")).contains(new HookViews.Refusal("ATTACKER", "WRONG_CASE"));
        assertThat(hook.designate("run-forced", "run-o")).contains(new HookViews.Refusal("ATTACKER", "FORCED"));
        assertThat(hook.designate("run-live", "run-o")).contains(new HookViews.Refusal("ATTACKER", "NOT_MEASURED"));
        assertThat(hook.designate("run-old", "run-o")).as("its texts passed the retention period")
                .contains(new HookViews.Refusal("ATTACKER", "TEXTS_GONE"));
        assertThat(hook.designate("run-a", "missing")).contains(new HookViews.Refusal("OWNER", "UNKNOWN_RUN"));
        assertThat(hook.designate("run-a", "run-other"))
                .contains(new HookViews.Refusal("OWNER", "DIFFERENT_MEASUREMENT"));
        assertThat(designated).isEmpty();
    }

    @Test
    void theTwoAreToldApartOnlyWhenEveryMeasuredRunSaysSo() {
        HookViews.Column stopped = column(Map.of("STOPPED", 3L));
        HookViews.Column passed = column(Map.of("PASSED", 2L, "PASSED_AFTER_CHECK", 1L));

        assertThat(HookViews.distinguished(stopped, passed)).isTrue();
        assertThat(HookViews.distinguished(column(Map.of("STOPPED", 2L, "MISSED", 1L)), passed)).isFalse();
        assertThat(HookViews.distinguished(stopped, column(Map.of("PASSED", 2L, "HALTED", 1L)))).isFalse();
        assertThat(HookViews.distinguished(stopped, column(Map.of()))).as("nothing measured").isFalse();
    }

    private static HookViews.Column column(Map<String, Long> results) {
        int runs = (int) results.values().stream().mapToLong(Long::longValue).sum();
        return new HookViews.Column("X", "run-x", NOW, null, null, Map.of(), null,
                new HookViews.Measurement("p-1", runs, runs, 0, results));
    }

    private static RunFacts facts(String runId, String caseKey, String status, String forced, String protocol,
                                  Instant firstText) {
        return new RunFacts(runId, caseKey, status, forced, protocol, firstText, firstText);
    }
}
