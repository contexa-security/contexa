package io.contexa.sandbox.fullstack.prompt;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

public final class SandboxDecisionBenchmarkExecutionMode {

    public enum Mode {
        NONE,
        PROMPT_HARVEST,
        REAL_DECISION_REPLAY
    }

    private static final AtomicReference<Mode> CURRENT = new AtomicReference<>(Mode.NONE);

    private SandboxDecisionBenchmarkExecutionMode() {
    }

    public static Mode current() {
        return CURRENT.get();
    }

    public static boolean isPromptHarvest() {
        return current() == Mode.PROMPT_HARVEST;
    }

    public static boolean isRealDecisionReplay() {
        return current() == Mode.REAL_DECISION_REPLAY;
    }

    public static void set(Mode mode) {
        CURRENT.set(Objects.requireNonNull(mode, "mode must not be null"));
    }

    public static void clear() {
        CURRENT.set(Mode.NONE);
    }

    public static <T> T withMode(Mode mode, Supplier<T> supplier) {
        Objects.requireNonNull(mode, "mode must not be null");
        Objects.requireNonNull(supplier, "supplier must not be null");
        Mode previous = CURRENT.getAndSet(mode);
        try {
            return supplier.get();
        } finally {
            CURRENT.set(previous);
        }
    }

    public static void runWithMode(Mode mode, Runnable runnable) {
        withMode(mode, () -> {
            runnable.run();
            return null;
        });
    }
}
