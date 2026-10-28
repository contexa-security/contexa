package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.combination.CombinationCatalog;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.RunSummary;
import io.contexa.showcase.portal.scenario.AgentTaskCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * docs/agent Agent중심-화면 AC-6: the live runs of agents are capped as a whole (five at once by default, never more
 * than eight). An agent run past the cap is refused at once, with no queue, and the check and the start are one step, so
 * starting many at the same moment never lets more than the cap in. Runs of people are not counted and not refused.
 */
class LiveRunsAgentCapTest {

    private final Map<String, CountDownLatch> holds = new ConcurrentHashMap<>();
    private final AtomicInteger runningAgents = new AtomicInteger();
    private final AtomicInteger mostAgentsAtOnce = new AtomicInteger();
    private final LiveRuns.Runner runner = (scenario, forced, responder, listener) -> {
        listener.runStarted("run-" + scenario.key());
        boolean agent = scenario.task() != null;
        if (agent) {
            mostAgentsAtOnce.accumulateAndGet(runningAgents.incrementAndGet(), Math::max);
        }
        try {
            hold(scenario.key()).await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            if (agent) {
                runningAgents.decrementAndGet();
            }
        }
        return new RunSummary("run-" + scenario.key(), scenario.key(), "u", "org", "COMPLETED", null, List.of());
    };
    private LiveRuns live;

    @AfterEach
    void close() {
        holds.values().forEach(CountDownLatch::countDown);
        if (live != null) {
            live.close();
        }
    }

    private LiveRuns live(int maxConcurrent, int maxQueue, int agentConcurrent) {
        live = new LiveRuns(runner, new LiveRuns.Settings(maxConcurrent, maxQueue, 0, Duration.ofMinutes(30),
                Duration.ofMinutes(15), List.of(), null, agentConcurrent), Clock.systemUTC());
        return live;
    }

    @Test
    void anAgentRunPastTheCapIsRefusedAtOnceWithoutAQueueWhilePeopleKeepRunning() throws Exception {
        LiveRuns runs = live(10, 5, 2);

        runs.start("v1", agent("T5"), summary -> { });
        runs.start("v2", agent("N1"), summary -> { });

        assertThat(runs.agentRunsActive()).isEqualTo(2);
        assertThatThrownBy(() -> runs.start("v3", agent("M13A"), summary -> { }))
                .isInstanceOf(LiveRuns.AgentBusy.class);
        assertThat(runs.waiting()).as("an agent run past the cap never waits").isZero();
        assertThat(runs.agentRunsActive()).isEqualTo(2);
        assertThat(runs.start("v4", CombinationCatalog.scenario(CombinationCatalog.all().get(0)), summary -> { }))
                .as("a person's run is not counted and not refused").isNotNull();
    }

    @Test
    void aFinishedAgentRunFreesItsPlace() throws Exception {
        LiveRuns runs = live(10, 5, 1);
        LiveRun first = runs.start("v1", agent("T5"), summary -> { });
        assertThatThrownBy(() -> runs.start("v2", agent("N1"), summary -> { })).isInstanceOf(LiveRuns.AgentBusy.class);

        hold("T5").countDown();
        await(() -> first.view().status() == LiveRun.Status.COMPLETED);
        await(() -> runs.agentRunsActive() == 0);

        assertThat(runs.start("v2", agent("N1"), summary -> { })).isNotNull();
        assertThat(runs.agentRunsActive()).isEqualTo(1);
    }

    @Test
    void anAgentRunWaitingForRoomCountsAgainstTheCapToo() throws Exception {
        // one place in all: the person's run holds it, so the first agent run waits in the queue
        LiveRuns runs = live(1, 5, 1);
        runs.start("v1", CombinationCatalog.scenario(CombinationCatalog.all().get(0)), summary -> { });
        LiveRun queued = runs.start("v2", agent("T5"), summary -> { });

        assertThat(queued.view().status()).isEqualTo(LiveRun.Status.QUEUED);
        assertThat(runs.agentRunsActive()).as("the queued agent run is counted").isEqualTo(1);
        assertThatThrownBy(() -> runs.start("v3", agent("N1"), summary -> { })).isInstanceOf(LiveRuns.AgentBusy.class);
    }

    @Test
    void theSameVisitorsRunStillComesBackWhenTheCapIsFull() throws Exception {
        LiveRuns runs = live(10, 5, 1);
        LiveRun mine = runs.start("v1", agent("T5"), summary -> { });

        assertThat(runs.start("v1", agent("T5"), summary -> { })).as("one run per visitor, not a new one").isSameAs(mine);
    }

    @Test
    void theCapIsNeverMoreThanEightWhateverIsConfiguredAndNeverBelowOne() {
        assertThat(settings(20).agentConcurrent()).isEqualTo(8);
        assertThat(settings(8).agentConcurrent()).isEqualTo(8);
        assertThat(settings(5).agentConcurrent()).isEqualTo(5);
        assertThat(settings(0).agentConcurrent()).isEqualTo(1);
        assertThat(settings(-3).agentConcurrent()).isEqualTo(1);
        assertThat(new LiveRuns.Settings(5, 5, 0, Duration.ofMinutes(30), Duration.ofMinutes(15), List.of(), null)
                .agentConcurrent()).as("the shorter form keeps the default of five").isEqualTo(5);
    }

    /** Many visitors start agent runs at the same moment, 50 times over (AC-6 (3)): the cap is never passed. */
    @Test
    void startsAtTheSameMomentNeverLetMoreThanTheCapIn() throws Exception {
        ObjectMapper json = new ObjectMapper().findAndRegisterModules();
        ScenarioDefinition task = new AgentTaskCatalog(json).find("T5").orElseThrow();
        for (int round = 0; round < 50; round++) {
            holds.clear();
            LiveRuns runs = live(50, 50, 3);
            ExecutorService pool = Executors.newFixedThreadPool(24);
            CountDownLatch go = new CountDownLatch(1);
            AtomicInteger accepted = new AtomicInteger();
            AtomicInteger refused = new AtomicInteger();
            List<Future<?>> futures = new ArrayList<>();
            for (int visitor = 0; visitor < 24; visitor++) {
                String id = "v" + round + "-" + visitor;
                futures.add(pool.submit(() -> {
                    go.await();
                    try {
                        runs.start(id, task, summary -> { });
                        accepted.incrementAndGet();
                    } catch (LiveRuns.AgentBusy e) {
                        refused.incrementAndGet();
                    }
                    return null;
                }));
            }
            go.countDown();
            for (Future<?> future : futures) {
                future.get(10, TimeUnit.SECONDS);
            }
            pool.shutdownNow();

            assertThat(accepted.get()).as("round %d accepted", round).isEqualTo(3);
            assertThat(refused.get()).as("round %d refused", round).isEqualTo(21);
            assertThat(runs.agentRunsActive()).isEqualTo(3);
            holds.values().forEach(CountDownLatch::countDown);
            runs.close();
        }
        assertThat(mostAgentsAtOnce.get()).as("no moment held more agent runs than the cap").isLessThanOrEqualTo(3);
    }

    private static LiveRuns.Settings settings(int agentConcurrent) {
        return new LiveRuns.Settings(5, 5, 0, Duration.ofMinutes(30), Duration.ofMinutes(15), List.of(), null,
                agentConcurrent);
    }

    private ScenarioDefinition agent(String key) throws IOException {
        return new AgentTaskCatalog(new ObjectMapper().findAndRegisterModules()).find(key).orElseThrow();
    }

    private CountDownLatch hold(String key) {
        return holds.computeIfAbsent(key, any -> new CountDownLatch(1));
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
}
