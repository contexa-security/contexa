package io.contexa.showcase.portal.live;

import io.contexa.showcase.portal.combination.Combination;
import io.contexa.showcase.portal.combination.CombinationCatalog;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.RunSummary;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Deck p.27 on the live spaces: a limit of concurrent runs, a limit of starts per minute that keeps the model provider
 * under its rate limit (docs/showcase/계획대조-검수.md N-1), a queue that tells its place, and space clean-up.
 */
class LiveRunsTest {

    private final MovableClock clock = new MovableClock(Instant.parse("2026-10-05T07:00:00Z"));
    private final Map<String, CountDownLatch> gates = new ConcurrentHashMap<>();
    private final List<String> finished = new CopyOnWriteArrayList<>();
    private final LiveRuns.Runner runner = (scenario, forced, responder, listener) -> {
        listener.runStarted("run-" + scenario.key());
        try {
            gate(scenario.key()).await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return new RunSummary("run-" + scenario.key(), scenario.key(), "u", "org", "COMPLETED", null, List.of());
    };
    private final LiveRuns live = new LiveRuns(runner,
            new LiveRuns.Settings(2, 2, 0, Duration.ofMinutes(30), Duration.ofMinutes(15), List.of(), null), clock);

    @AfterEach
    void close() {
        gates.values().forEach(CountDownLatch::countDown);
        live.close();
    }

    @Test
    void runsBeyondTheLimitWaitInTheQueueAndMoveUpWhenOneFinishes() throws Exception {
        LiveRun first = start("v1", 0);
        LiveRun second = start("v2", 1);
        LiveRun third = start("v3", 2);
        LiveRun fourth = start("v4", 3);

        assertThat(first.view().status()).isNotEqualTo(LiveRun.Status.QUEUED);
        assertThat(second.view().status()).isNotEqualTo(LiveRun.Status.QUEUED);
        assertThat(third.view().queuePosition()).isEqualTo(1);
        assertThat(fourth.view().queuePosition()).isEqualTo(2);
        assertThatThrownBy(() -> start("v5", 4)).isInstanceOf(LiveRuns.Busy.class);
        assertThat(live.hasRoom()).isFalse();
        assertThat(start("v1", 5)).as("one run per visitor").isSameAs(first);

        gate(cell(0).key()).countDown();
        await(() -> first.view().status() == LiveRun.Status.COMPLETED);
        await(() -> third.view().status() != LiveRun.Status.QUEUED);
        assertThat(fourth.view().queuePosition()).isEqualTo(1);
        await(() -> finished.contains(cell(0).key()));
        assertThat(live.running()).isEqualTo(2);
        assertThat(live.waiting()).isEqualTo(1);
    }

    @Test
    void runsBeyondTheStartRateWaitForTheNextMinuteEvenWithRoom() throws Exception {
        try (LiveRuns rated = new LiveRuns(runner,
                new LiveRuns.Settings(10, 5, 2, Duration.ofMinutes(30), Duration.ofMinutes(15), List.of(), null),
                clock)) {
            LiveRun first = rated.start("v1", CombinationCatalog.scenario(cell(0)), summary -> { });
            LiveRun second = rated.start("v2", CombinationCatalog.scenario(cell(1)), summary -> { });
            LiveRun third = rated.start("v3", CombinationCatalog.scenario(cell(2)), summary -> { });

            assertThat(first.view().status()).isNotEqualTo(LiveRun.Status.QUEUED);
            assertThat(second.view().status()).isNotEqualTo(LiveRun.Status.QUEUED);
            assertThat(third.view().queuePosition()).as("two starts this minute already").isEqualTo(1);
            assertThat(rated.startsInLastMinute()).isEqualTo(2);

            rated.dispatch();
            assertThat(third.view().status()).as("still the same minute").isEqualTo(LiveRun.Status.QUEUED);

            clock.move(Duration.ofSeconds(61));
            rated.dispatch();
            assertThat(third.view().status()).isNotEqualTo(LiveRun.Status.QUEUED);
            assertThat(rated.startsInLastMinute()).isEqualTo(1);
        }
    }

    @Test
    void anInactiveSpaceLeavesTheQueueWhileRunningSpacesStay() throws Exception {
        start("v1", 0);
        start("v2", 1);
        LiveRun third = start("v3", 2);
        LiveRun fourth = start("v4", 3);

        clock.move(Duration.ofMinutes(16));
        live.current("v4");
        int removed = live.sweep();

        assertThat(removed).isEqualTo(1);
        assertThat(third.view().status()).isEqualTo(LiveRun.Status.EXPIRED);
        assertThat(live.current("v3")).isEmpty();
        assertThat(fourth.view().queuePosition()).isEqualTo(1);
        assertThat(live.spaces()).as("running spaces stay until their run ends").isEqualTo(3);
    }

    private CountDownLatch gate(String key) {
        return gates.computeIfAbsent(key, any -> new CountDownLatch(1));
    }

    private LiveRun start(String visitor, int index) {
        ScenarioDefinition scenario = CombinationCatalog.scenario(cell(index));
        return live.start(visitor, scenario, summary -> finished.add(summary.scenarioKey()));
    }

    private static Combination cell(int index) {
        return CombinationCatalog.all().get(index);
    }

    private static void await(BooleanSupplier condition) throws InterruptedException {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < until) {
            if (condition.getAsBoolean()) {
                return;
            }
            Thread.sleep(10);
        }
        throw new AssertionError("condition not reached");
    }

    private static final class MovableClock extends Clock {

        private volatile Instant now;

        MovableClock(Instant now) {
            this.now = now;
        }

        void move(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
