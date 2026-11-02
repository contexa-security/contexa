package io.contexa.contexacore.std.llm.gate;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * O-1 reproduced with a fake server that loads one model at a time and runs two requests at once, the way a local
 * Ollama with one GPU does: requests of the loaded model are handed to it as they come, and a request for another
 * model waits, with everything behind it, until every request handed to the loaded model is done. A burst of decisions
 * then starves the embedding of a vector store write past its time limit; through the gate it is not.
 */
class ModelServerStarvationTest {

    private static final long CHAT_MS = 200L;
    private static final long EMBEDDING_MS = 20L;
    private static final long SWITCH_MS = 100L;
    private static final long STORE_LIMIT_MS = 500L;
    private static final int CHATS = 12;

    @Test
    void withoutTheGateABurstOfChatsStarvesTheEmbeddingPastItsLimit() throws Exception {
        FakeOneModelServer server = new FakeOneModelServer();
        ExecutorService callers = Executors.newCachedThreadPool();
        try {
            List<Future<?>> chats = startChats(callers, () -> server.call("qwen3:8b", CHAT_MS));
            Thread.sleep(50);
            ModelCallTimer store = ModelCallTimer.start(STORE_LIMIT_MS);
            Future<String> embedding = callers.submit(store.bind(() -> {
                server.call("mxbai-embed-large", EMBEDDING_MS);
                return "stored";
            }));

            assertThatThrownBy(() -> store.await(embedding)).isInstanceOf(TimeoutException.class);
            awaitAll(chats);
        } finally {
            callers.shutdownNow();
        }
    }

    @Test
    void throughTheGateTheEmbeddingIsStoredWithinItsLimit() throws Exception {
        FakeOneModelServer server = new FakeOneModelServer();
        ModelServerGate gate = new ModelServerGate(ModelServer.of("ollama", "http://localhost:11434"), 2, true,
                Duration.ZERO);
        ExecutorService callers = Executors.newCachedThreadPool();
        try {
            List<Future<?>> chats = startChats(callers, () -> {
                try (ModelServerGate.Permit ignored = gate.enter(CallKind.CHAT, "qwen3:8b", 30_000L)) {
                    server.call("qwen3:8b", CHAT_MS);
                }
            });
            Thread.sleep(50);
            ModelCallTimer store = ModelCallTimer.start(STORE_LIMIT_MS);
            long started = System.nanoTime();
            Future<String> embedding = callers.submit(store.bind(() -> {
                try (ModelServerGate.Permit ignored = gate.enter(CallKind.EMBEDDING, "mxbai-embed-large", 30_000L)) {
                    server.call("mxbai-embed-large", EMBEDDING_MS);
                }
                return "stored";
            }));

            assertThat(store.await(embedding)).isEqualTo("stored");
            // It waited only for the chats already running, not for the whole burst.
            assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started))
                    .isLessThan(CHAT_MS * CHATS / 2);
            awaitAll(chats);
            assertThat(server.mostAtOnce()).isLessThanOrEqualTo(2);
        } finally {
            callers.shutdownNow();
        }
    }

    private static List<Future<?>> startChats(ExecutorService callers, ThrowingRunnable chat) {
        List<Future<?>> chats = new ArrayList<>();
        for (int i = 0; i < CHATS; i++) {
            chats.add(callers.submit(() -> {
                chat.run();
                return null;
            }));
        }
        return chats;
    }

    private static void awaitAll(List<Future<?>> futures) throws Exception {
        for (Future<?> future : futures) {
            future.get(30, TimeUnit.SECONDS);
        }
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    /** One model loaded at a time, two requests at once, a model switch only when the loaded model is idle. */
    private static final class FakeOneModelServer {

        private final Semaphore slots = new Semaphore(2, true);
        private final Deque<Object> pending = new ArrayDeque<>();
        private String loaded;
        private int handedToLoaded;
        private int running;
        private int mostAtOnce;

        void call(String model, long workMs) throws InterruptedException {
            Object ticket = new Object();
            boolean switching;
            synchronized (this) {
                if (pending.isEmpty() && (loaded == null || loaded.equals(model))) {
                    loaded = model;
                    handedToLoaded++;
                    switching = false;
                } else {
                    pending.addLast(ticket);
                    while (pending.peekFirst() != ticket || (handedToLoaded > 0 && !model.equals(loaded))) {
                        wait();
                    }
                    pending.removeFirst();
                    switching = !model.equals(loaded);
                    loaded = model;
                    handedToLoaded++;
                    notifyAll();
                }
            }
            if (switching) {
                Thread.sleep(SWITCH_MS);
            }
            slots.acquire();
            try {
                synchronized (this) {
                    running++;
                    mostAtOnce = Math.max(mostAtOnce, running);
                }
                Thread.sleep(workMs);
            } finally {
                synchronized (this) {
                    running--;
                    handedToLoaded--;
                    notifyAll();
                }
                slots.release();
            }
        }

        synchronized int mostAtOnce() {
            return mostAtOnce;
        }
    }
}
