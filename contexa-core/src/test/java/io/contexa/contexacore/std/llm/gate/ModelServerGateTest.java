package io.contexa.contexacore.std.llm.gate;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * O-1: every call to one model server passes one gate. It caps the calls running at once, lets embeddings in before
 * waiting chats, switches a self-hosted server's model only when the calls of the loaded model are done, and keeps
 * a server that signalled overload closed for a while.
 */
class ModelServerGateTest {

    private static final ModelServer LOCAL = ModelServer.of("ollama", "http://localhost:11434");

    @Test
    void noMoreCallsRunAtOnceThanTheServerTakes() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 2, false, Duration.ZERO);
        AtomicInteger running = new AtomicInteger();
        AtomicInteger mostAtOnce = new AtomicInteger();
        ExecutorService callers = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> calls = new CopyOnWriteArrayList<>();
            for (int i = 0; i < 8; i++) {
                calls.add(callers.submit(() -> {
                    try (ModelServerGate.Permit ignored = gate.enter(CallKind.CHAT, "qwen3:8b", 10_000L)) {
                        mostAtOnce.accumulateAndGet(running.incrementAndGet(), Math::max);
                        Thread.sleep(50);
                        running.decrementAndGet();
                    }
                    return null;
                }));
            }
            for (Future<?> call : calls) {
                call.get(10, TimeUnit.SECONDS);
            }
        } finally {
            callers.shutdownNow();
        }

        assertThat(mostAtOnce).hasValue(2);
    }

    @Test
    void aWaitingEmbeddingGoesInBeforeChatsThatCameEarlier() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 1, false, Duration.ZERO);
        List<String> order = new CopyOnWriteArrayList<>();
        ModelServerGate.Permit first = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L);
        ExecutorService callers = Executors.newFixedThreadPool(2);
        try {
            Future<?> chat = callers.submit(() -> enterAndRecord(gate, CallKind.CHAT, "qwen3:8b", order, "chat"));
            awaitWaiters(gate, 1);
            Future<?> embedding = callers.submit(() -> enterAndRecord(gate, CallKind.EMBEDDING, "qwen3:8b", order,
                    "embedding"));
            awaitWaiters(gate, 2);

            first.close();
            chat.get(5, TimeUnit.SECONDS);
            embedding.get(5, TimeUnit.SECONDS);
        } finally {
            callers.shutdownNow();
        }

        assertThat(order).containsExactly("embedding", "chat");
    }

    /** Q-23: the first decision of a session goes in before the calls of sessions that have one, not before embeddings. */
    @Test
    void aFirstDecisionGoesInBeforeChatsThatCameEarlierInTheOrderTheFirstDecisionsCame() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 1, false, Duration.ZERO);
        List<String> order = new CopyOnWriteArrayList<>();
        ModelServerGate.Permit running = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L);
        ExecutorService callers = Executors.newFixedThreadPool(4);
        try {
            Future<?> chat = callers.submit(() -> enterAndRecord(gate, CallKind.CHAT, "qwen3:8b", order, "chat"));
            awaitWaiters(gate, 1);
            Future<?> firstDecision = callers.submit(() -> enterFirstInLine(gate, order, "first-1"));
            awaitWaiters(gate, 2);
            Future<?> secondFirstDecision = callers.submit(() -> enterFirstInLine(gate, order, "first-2"));
            awaitWaiters(gate, 3);
            Future<?> embedding = callers.submit(() -> enterAndRecord(gate, CallKind.EMBEDDING, "qwen3:8b", order,
                    "embedding"));
            awaitWaiters(gate, 4);

            running.close();
            chat.get(5, TimeUnit.SECONDS);
            firstDecision.get(5, TimeUnit.SECONDS);
            secondFirstDecision.get(5, TimeUnit.SECONDS);
            embedding.get(5, TimeUnit.SECONDS);
        } finally {
            callers.shutdownNow();
        }

        assertThat(order).containsExactly("embedding", "first-1", "first-2", "chat");
    }

    private static Void enterFirstInLine(ModelServerGate gate, List<String> order, String name) throws Exception {
        ModelCallTimer timer = ModelCallTimer.start(10_000L).firstInLine(true);
        try (ModelServerGate.Permit ignored = gate.enter(CallKind.CHAT, "qwen3:8b", 5_000L, timer)) {
            order.add(name);
        }
        return null;
    }

    @Test
    void aTimerInsideOneOfAFirstDecisionIsOneToo() {
        ModelCallTimer outer = ModelCallTimer.start(1_000L).firstInLine(true);

        assertThat(outer.child(100L).firstInLine()).isTrue();
        assertThat(ModelCallTimer.start(1_000L).firstInLine()).isFalse();
    }

    @Test
    void aSelfHostedServerSwitchesItsModelOnlyWhenTheLoadedModelsCallsAreDone() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 2, true, Duration.ZERO);
        List<String> order = new CopyOnWriteArrayList<>();
        ModelServerGate.Permit chat = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L);
        ExecutorService callers = Executors.newFixedThreadPool(2);
        try {
            Future<?> embedding = callers.submit(() -> enterAndRecord(gate, CallKind.EMBEDDING, "mxbai-embed-large",
                    order, "embedding"));
            awaitWaiters(gate, 1);
            // A free slot is not enough: the server would only queue the embedding behind the running chat.
            Thread.sleep(100);
            assertThat(order).isEmpty();
            // A chat of the loaded model that comes later waits behind the switch instead of starving it.
            Future<?> laterChat = callers.submit(() -> enterAndRecord(gate, CallKind.CHAT, "qwen3:8b", order,
                    "later chat"));
            awaitWaiters(gate, 2);
            Thread.sleep(100);
            assertThat(order).isEmpty();

            chat.close();
            embedding.get(5, TimeUnit.SECONDS);
            laterChat.get(5, TimeUnit.SECONDS);
        } finally {
            callers.shutdownNow();
        }

        assertThat(order).containsExactly("embedding", "later chat");
    }

    @Test
    void callsOfTheLoadedModelShareTheServer() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 2, true, Duration.ZERO);
        try (ModelServerGate.Permit first = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L);
             ModelServerGate.Permit second = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L)) {
            assertThat(gate.running()).isEqualTo(2);
        }
        assertThat(gate.running()).isZero();
    }

    @Test
    void aCallThatCannotGetInWithinItsWaitEndsAsServerBusy() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 1, false, Duration.ZERO);
        try (ModelServerGate.Permit ignored = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L)) {
            long started = System.nanoTime();
            assertThatThrownBy(() -> gate.enter(CallKind.CHAT, "qwen3:8b", 150L))
                    .isInstanceOf(ModelServerBusyException.class)
                    .hasMessageContaining("localhost:11434");
            assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)).isGreaterThanOrEqualTo(140L);
        }
        assertThat(gate.waiting()).isZero();
    }

    @Test
    void anInterruptedWaiterLeavesTheLine() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 1, false, Duration.ZERO);
        ModelServerGate.Permit held = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L);
        CountDownLatch interrupted = new CountDownLatch(1);
        Thread waiter = new Thread(() -> {
            try {
                gate.enter(CallKind.CHAT, "qwen3:8b", 10_000L).close();
            } catch (InterruptedException expected) {
                interrupted.countDown();
            }
        });
        waiter.start();
        awaitWaiters(gate, 1);
        waiter.interrupt();

        assertThat(interrupted.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(gate.waiting()).isZero();
        held.close();
        assertThat(gate.running()).isZero();
    }

    /**
     * A waiter that leaves the line removes itself and no other: with three equal waiters in line, the one in the middle
     * timing out must leave the first and the last in place, so that the first goes in when the slot is free. A line that
     * dropped the first instead left the middle one's entry at its head, and nobody went in until the next timeout.
     */
    @Test
    void aWaiterThatTimesOutInTheMiddleOfTheLineLeavesTheOnesAroundItInPlace() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 1, false, Duration.ZERO);
        ModelServerGate.Permit held = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L);
        List<String> order = new CopyOnWriteArrayList<>();
        ExecutorService callers = Executors.newFixedThreadPool(3);
        try {
            Future<?> first = callers.submit(() -> enterAndRecord(gate, CallKind.CHAT, "qwen3:8b", order, "first"));
            awaitWaiters(gate, 1);
            Future<?> middle = callers.submit(() -> {
                try (ModelServerGate.Permit ignored = gate.enter(CallKind.CHAT, "qwen3:8b", 150L)) {
                    order.add("middle");
                }
                return null;
            });
            awaitWaiters(gate, 2);
            Future<?> last = callers.submit(() -> enterAndRecord(gate, CallKind.CHAT, "qwen3:8b", order, "last"));
            awaitWaiters(gate, 3);

            assertThatThrownBy(() -> middle.get(5, TimeUnit.SECONDS))
                    .hasCauseInstanceOf(ModelServerBusyException.class);
            assertThat(gate.waiting()).isEqualTo(2);

            held.close();
            first.get(1, TimeUnit.SECONDS);
            last.get(1, TimeUnit.SECONDS);
        } finally {
            callers.shutdownNow();
        }

        assertThat(order).containsExactly("first", "last");
        assertThat(gate.running()).isZero();
        assertThat(gate.waiting()).isZero();
    }

    /** The same for a waiter interrupted in the middle of the line. */
    @Test
    void aWaiterInterruptedInTheMiddleOfTheLineLeavesTheOnesAroundItInPlace() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 1, false, Duration.ZERO);
        ModelServerGate.Permit held = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L);
        List<String> order = new CopyOnWriteArrayList<>();
        ExecutorService callers = Executors.newFixedThreadPool(2);
        CountDownLatch interrupted = new CountDownLatch(1);
        try {
            Future<?> first = callers.submit(() -> enterAndRecord(gate, CallKind.CHAT, "qwen3:8b", order, "first"));
            awaitWaiters(gate, 1);
            Thread middle = new Thread(() -> {
                try {
                    gate.enter(CallKind.CHAT, "qwen3:8b", 10_000L).close();
                } catch (InterruptedException expected) {
                    interrupted.countDown();
                }
            });
            middle.start();
            awaitWaiters(gate, 2);
            Future<?> last = callers.submit(() -> enterAndRecord(gate, CallKind.CHAT, "qwen3:8b", order, "last"));
            awaitWaiters(gate, 3);

            middle.interrupt();
            assertThat(interrupted.await(5, TimeUnit.SECONDS)).isTrue();
            assertThat(gate.waiting()).isEqualTo(2);

            held.close();
            first.get(1, TimeUnit.SECONDS);
            last.get(1, TimeUnit.SECONDS);
        } finally {
            callers.shutdownNow();
        }

        assertThat(order).containsExactly("first", "last");
    }

    /** How long a chat call holds its slot is measured, so that the analyses can be sized to what the server serves. */
    @Test
    void theTimeAChatCallHoldsItsSlotIsKeptAsAMovingAverage() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 2, false, Duration.ZERO);
        assertThat(gate.chatCallMillis()).isZero();

        gate.recordChatCall(TimeUnit.SECONDS.toNanos(10));
        assertThat(gate.chatCallMillis()).isEqualTo(10_000L);

        gate.recordChatCall(TimeUnit.SECONDS.toNanos(5));
        assertThat(gate.chatCallMillis()).isBetween(8_000L, 9_999L);
    }

    @Test
    void aChatCallThatEndsSetsTheTimeItHeldItsSlot() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 2, false, Duration.ZERO);

        try (ModelServerGate.Permit ignored = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L)) {
            Thread.sleep(60);
        }

        assertThat(gate.chatCallMillis()).isBetween(50L, 5_000L);
    }

    @Test
    void anEmbeddingAnOverloadedCallAndACallInsideACallDoNotCount() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 2, false, Duration.ZERO);

        try (ModelServerGate.Permit ignored = gate.enter(CallKind.EMBEDDING, "mxbai", 1_000L)) {
            Thread.sleep(30);
        }
        try (ModelServerGate.Permit rateLimited = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L)) {
            Thread.sleep(30);
            rateLimited.overloaded();
        }
        assertThat(gate.chatCallMillis()).isZero();

        try (ModelServerGate.Permit outer = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L)) {
            outer.scope(() -> {
                try (ModelServerGate.Permit inner = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L)) {
                    Thread.sleep(200);
                }
                return null;
            }).call();
        }

        // the call inside the call is the outer call's own time, counted once, not twice
        assertThat(gate.chatCallMillis()).isBetween(150L, 2_000L);
    }

    /** A server that has taken no chat call, an embedding server, is told from one that has: it does not bound the analyses. */
    @Test
    void aGateKnowsWhetherItHasTakenAChatCall() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 2, false, Duration.ZERO);
        assertThat(gate.chatCallsSeen()).isFalse();

        gate.enter(CallKind.EMBEDDING, "mxbai", 1_000L).close();
        assertThat(gate.chatCallsSeen()).isFalse();

        gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L).close();
        assertThat(gate.chatCallsSeen()).isTrue();
    }

    @Test
    void anOverloadSignalKeepsTheServerClosedForAWhile() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 2, false, Duration.ofMillis(300));
        ModelServerGate.Permit failed = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L);
        failed.overloaded();
        failed.close();

        long started = System.nanoTime();
        try (ModelServerGate.Permit ignored = gate.enter(CallKind.CHAT, "qwen3:8b", 5_000L)) {
            assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)).isGreaterThanOrEqualTo(250L);
        }
        // A call that went through ends the back-off.
        long next = System.nanoTime();
        gate.enter(CallKind.CHAT, "qwen3:8b", 5_000L).close();
        assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - next)).isLessThan(100L);
    }

    @Test
    void theWaitIsLeftOutOfTheCallersTimeLimits() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 1, false, Duration.ZERO);
        ModelServerGate.Permit held = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L);
        ModelCallTimer layer = ModelCallTimer.start(10_000L);
        ModelCallTimer vector = layer.child(10_000L);
        Thread waiter = new Thread(vector.bind(() -> {
            try {
                gate.enter(CallKind.EMBEDDING, "mxbai-embed-large", 5_000L).close();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }));
        waiter.start();
        awaitWaiters(gate, 1);
        Thread.sleep(300);
        held.close();
        waiter.join(5_000L);

        assertThat(vector.excludedMillis()).isGreaterThanOrEqualTo(250L);
        assertThat(layer.excludedMillis()).isGreaterThanOrEqualTo(250L);
    }

    /**
     * A tool or an advisor running inside a call may call the same server again (a vector search, a query rewrite).
     * The nested call goes in under the slot of the call it runs in; waiting for a slot of its own would wait for the
     * call that waits for it.
     */
    @Test
    void aCallMadeInsideACallThatIsInGoesInUnderItsSlot() throws Exception {
        ModelServerGate gate = new ModelServerGate(LOCAL, 1, true, Duration.ZERO);
        ModelServerGate.Permit outer = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L);
        ExecutorService providerThread = Executors.newSingleThreadExecutor();
        try {
            Future<String> call = providerThread.submit(outer.scope(() -> {
                try (ModelServerGate.Permit nested = gate.enter(CallKind.EMBEDDING, "mxbai-embed-large", 300L)) {
                    return "nested call in";
                }
            }));

            assertThat(call.get(5, TimeUnit.SECONDS)).isEqualTo("nested call in");
            assertThat(gate.running()).isEqualTo(1);
        } finally {
            providerThread.shutdownNow();
            outer.close();
        }
        assertThat(gate.running()).isZero();
        // Outside the scope the same thread waits for a slot of its own again.
        try (ModelServerGate.Permit held = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L)) {
            assertThatThrownBy(() -> gate.enter(CallKind.CHAT, "qwen3:8b", 100L))
                    .isInstanceOf(ModelServerBusyException.class);
        }
    }

    private static Void enterAndRecord(ModelServerGate gate, CallKind kind, String model, List<String> order,
                                       String name) throws InterruptedException {
        try (ModelServerGate.Permit ignored = gate.enter(kind, model, 5_000L)) {
            order.add(name);
        }
        return null;
    }

    private static void awaitWaiters(ModelServerGate gate, int count) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (gate.waiting() < count && System.nanoTime() < deadline) {
            Thread.sleep(5);
        }
        assertThat(gate.waiting()).isEqualTo(count);
    }
}
