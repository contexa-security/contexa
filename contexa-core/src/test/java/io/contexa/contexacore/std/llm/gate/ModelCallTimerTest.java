package io.contexa.contexacore.std.llm.gate;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * O-1 (3): a time limit on work that calls a model counts from the call's start; the wait at the model server's gate
 * is left out, and the event's budget bounds it instead.
 */
class ModelCallTimerTest {

    private static final ModelServer LOCAL = ModelServer.of("ollama", "http://localhost:11434");

    @Test
    void aWaitAtTheGateIsNotCountedAgainstTheLimit() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 1, false, Duration.ZERO);
        ModelServerGate.Permit busy = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        Thread release = new Thread(() -> {
            sleep(600);
            busy.close();
        });
        try {
            ModelCallTimer timer = ModelCallTimer.start(400L);
            Future<String> work = worker.submit(timer.bind(() -> {
                try (ModelServerGate.Permit ignored = gate.enter(CallKind.EMBEDDING, "mxbai-embed-large", 5_000L)) {
                    sleep(150);
                    return "stored";
                }
            }));
            release.start();

            assertThat(timer.await(work)).isEqualTo("stored");
        } finally {
            worker.shutdownNow();
        }
    }

    @Test
    void workLongerThanTheLimitStillTimesOut() {
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            ModelCallTimer timer = ModelCallTimer.start(150L);
            Future<String> work = worker.submit(timer.bind(() -> {
                sleep(2_000);
                return "late";
            }));

            long started = System.currentTimeMillis();
            assertThatThrownBy(() -> timer.await(work)).isInstanceOf(TimeoutException.class);
            assertThat(System.currentTimeMillis() - started).isLessThan(1_500L);
        } finally {
            worker.shutdownNow();
        }
    }

    @Test
    void aChildTakesTheEarliestDeadlineOfItsParents() {
        long eventDeadline = System.currentTimeMillis() + 5_000L;
        ModelCallTimer layer = ModelCallTimer.start(60_000L).withDeadline(eventDeadline);
        ModelCallTimer vector = layer.child(15_000L);

        assertThat(vector.deadline()).isEqualTo(eventDeadline);
        assertThat(vector.withDeadline(eventDeadline - 1_000L).deadline()).isEqualTo(eventDeadline - 1_000L);
    }

    @Test
    void theCurrentTimerIsTheBoundOneOnlyWhileTheWorkRuns() throws Exception {
        ModelCallTimer timer = ModelCallTimer.start(1_000L);
        assertThat(ModelCallTimer.current()).isNull();
        assertThat(timer.bind(ModelCallTimer::current).call()).isSameAs(timer);
        assertThat(ModelCallTimer.current()).isNull();
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
