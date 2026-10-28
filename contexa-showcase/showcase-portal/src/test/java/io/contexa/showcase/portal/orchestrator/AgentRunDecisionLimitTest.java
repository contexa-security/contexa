package io.contexa.showcase.portal.orchestrator;

import io.contexa.showcase.portal.agent.AgentRunCap;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * docs/agent Agent중심-화면 AC-3: the decision limit of a visitor's live run is checked in the step that takes the
 * number of the run's next request, so the agent and the workers beside it cannot pass it together.
 */
class AgentRunDecisionLimitTest {

    @Test
    void aRunWithoutACapTakesNumbersWithoutALimit() throws IOException {
        AtomicInteger steps = new AtomicInteger(3);

        assertThat(RunOrchestrator.nextStep(steps, null)).isEqualTo(4);
        assertThat(RunOrchestrator.nextStep(steps, null)).isEqualTo(5);
    }

    @Test
    void aLiveRunTakesNumbersUpToItsLimitAndThenRefusesWithoutTakingOne() throws IOException {
        AtomicInteger steps = new AtomicInteger(2);
        AgentRunCap cap = new AgentRunCap(new AgentRunCap.Limits(12, 4, 40_000));

        assertThat(RunOrchestrator.nextStep(steps, cap)).isEqualTo(3);
        assertThat(RunOrchestrator.nextStep(steps, cap)).isEqualTo(4);
        assertThatThrownBy(() -> RunOrchestrator.nextStep(steps, cap)).isInstanceOf(IOException.class)
                .hasMessageContaining("decision limit");

        assertThat(steps.get()).as("a refused request takes no number").isEqualTo(4);
        assertThat(cap.reached()).isEqualTo(AgentRunCap.DECISIONS);
    }

    @Test
    void workersSendingTogetherNeverPassTheLimit() throws Exception {
        int limit = 20;
        int person = 4;
        AtomicInteger steps = new AtomicInteger(person);
        AgentRunCap cap = new AgentRunCap(new AgentRunCap.Limits(12, limit, 40_000));
        int workers = 16;
        CountDownLatch start = new CountDownLatch(1);
        List<Integer> numbers = Collections.synchronizedList(new ArrayList<>());
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        try {
            List<Future<?>> done = new ArrayList<>();
            for (int worker = 0; worker < workers; worker++) {
                done.add(pool.submit(() -> {
                    start.await();
                    for (int request = 0; request < 10; request++) {
                        try {
                            numbers.add(RunOrchestrator.nextStep(steps, cap));
                        } catch (IOException e) {
                            // refused at the limit
                        }
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> future : done) {
                future.get(10, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        assertThat(numbers).as("160 tried; only the limit's room is taken").hasSize(limit - person);
        assertThat(numbers).doesNotHaveDuplicates().allMatch(number -> number > person && number <= limit);
        assertThat(steps.get()).isEqualTo(limit);
    }

    @Test
    void theOperatorsMeasurementPathIsNotALiveRun() {
        // the cap is made only for a run whose listener names a visitor; the measurement path's listener names none
        assertThat(RunListener.NONE.liveVisitor()).isNull();
    }

    @Test
    void theDefaultLimitsAreTheOnesOfThePlan() {
        assertThat(AgentRunCap.Limits.defaults()).isEqualTo(new AgentRunCap.Limits(12, 20, 40_000));
    }
}
