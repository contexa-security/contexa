package io.contexa.contexacore.std.llm.bulkhead;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public final class OllamaBulkheadRegistry {

    private static final ConcurrentHashMap<String, Semaphore> SEMAPHORES = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, CircuitState> CIRCUITS = new ConcurrentHashMap<>();

    private OllamaBulkheadRegistry() {
    }

    public static Semaphore getSemaphore(String key, int permits) {
        return SEMAPHORES.computeIfAbsent(key, ignored -> new Semaphore(Math.max(1, permits), true));
    }

    public static CircuitState getCircuit(String key) {
        return CIRCUITS.computeIfAbsent(key, ignored -> new CircuitState());
    }

    static void resetForTests() {
        SEMAPHORES.clear();
        CIRCUITS.clear();
    }

    public static final class CircuitState {
        private final AtomicInteger consecutiveBusyFailures = new AtomicInteger(0);
        private final AtomicLong openUntilEpochMs = new AtomicLong(0L);

        public int incrementBusyFailures() {
            return consecutiveBusyFailures.incrementAndGet();
        }

        public void resetBusyFailures() {
            consecutiveBusyFailures.set(0);
            openUntilEpochMs.set(0L);
        }

        public void openUntil(long epochMs) {
            openUntilEpochMs.set(epochMs);
        }

        public boolean isOpen(long nowEpochMs) {
            return openUntilEpochMs.get() > nowEpochMs;
        }

        public long openUntilEpochMs() {
            return openUntilEpochMs.get();
        }
    }
}
