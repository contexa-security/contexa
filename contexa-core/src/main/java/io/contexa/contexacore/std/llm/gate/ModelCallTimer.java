/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.llm.gate;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * A time limit on work that calls a model, counted from the work's start without the time it waits at a model server's
 * gate (O-1 (3)). The wait is bounded by the event's budget instead: the earliest deadline of the timer and its
 * parents, which the gate takes as the longest it lets a call wait.
 * <p>
 * The work runs with the timer bound to its thread ({@link #bind(Callable)}); a timer started there has it as its
 * parent, so a wait in a nested piece of work (the embedding of a vector store write inside a layer's analysis) is left
 * out of every limit around it.
 */
public final class ModelCallTimer {

    private static final ThreadLocal<ModelCallTimer> CURRENT = new ThreadLocal<>();
    /** How long an await waits at a time while the work waits at a gate. */
    private static final long PAUSED_POLL_NANOS = TimeUnit.MILLISECONDS.toNanos(20);

    private final ModelCallTimer parent;
    private final long limitNanos;
    private final long startNanos = System.nanoTime();
    private volatile long deadline;
    private int waits;
    private long waitStartedNanos;
    private long excludedNanos;

    private ModelCallTimer(ModelCallTimer parent, long limitMs) {
        this.parent = parent;
        this.limitNanos = TimeUnit.MILLISECONDS.toNanos(Math.max(1L, limitMs));
    }

    /** A timer of the given limit; the timer bound to this thread, if any, is its parent. */
    public static ModelCallTimer start(long limitMs) {
        return new ModelCallTimer(CURRENT.get(), limitMs);
    }

    /** The timer bound to this thread, or null. */
    public static ModelCallTimer current() {
        return CURRENT.get();
    }

    /** A timer of the given limit inside this one. */
    public ModelCallTimer child(long limitMs) {
        return new ModelCallTimer(this, limitMs);
    }

    /** Sets the event's deadline (epoch milliseconds) when it is earlier than the one this timer has. */
    public ModelCallTimer withDeadline(long epochMillis) {
        if (epochMillis > 0L && (deadline <= 0L || epochMillis < deadline)) {
            deadline = epochMillis;
        }
        return this;
    }

    /** The earliest deadline of this timer and its parents (epoch milliseconds), or 0 when none has one. */
    public long deadline() {
        long own = deadline;
        long inherited = parent != null ? parent.deadline() : 0L;
        if (own <= 0L) {
            return inherited;
        }
        return inherited <= 0L ? own : Math.min(own, inherited);
    }

    /** The work, with this timer bound to the thread that runs it. */
    public <T> Callable<T> bind(Callable<T> work) {
        return () -> {
            ModelCallTimer previous = CURRENT.get();
            CURRENT.set(this);
            try {
                return work.call();
            } finally {
                restore(previous);
            }
        };
    }

    /** The work, with this timer bound to the thread that runs it. */
    public Runnable bind(Runnable work) {
        return () -> {
            ModelCallTimer previous = CURRENT.get();
            CURRENT.set(this);
            try {
                work.run();
            } finally {
                restore(previous);
            }
        };
    }

    /**
     * The work's result, waited for as long as the limit allows, not counting the time the work waited at a gate.
     *
     * @throws TimeoutException when the work ran longer than the limit
     */
    public <T> T await(Future<T> work) throws InterruptedException, ExecutionException, TimeoutException {
        while (true) {
            long remaining = remainingNanos();
            if (remaining <= 0L) {
                throw new TimeoutException("Work exceeded its time limit of "
                        + TimeUnit.NANOSECONDS.toMillis(limitNanos) + "ms (not counting "
                        + excludedMillis() + "ms of waiting for a model server)");
            }
            long wait = isWaiting() ? Math.max(remaining, PAUSED_POLL_NANOS) : remaining;
            try {
                return work.get(wait, TimeUnit.NANOSECONDS);
            } catch (TimeoutException stillRunning) {
                // A wait at a gate may have stopped the clock meanwhile: look again.
            }
        }
    }

    /** How long the work has waited at a gate so far, in milliseconds. */
    public long excludedMillis() {
        return TimeUnit.NANOSECONDS.toMillis(excludedNanos());
    }

    /** The time the limit has left, not counting the waits at a gate. */
    long remainingNanos() {
        return limitNanos - (System.nanoTime() - startNanos - excludedNanos());
    }

    /** A wait at a gate began: this timer and its parents stop until it ends. */
    void waitStarted() {
        synchronized (this) {
            if (waits++ == 0) {
                waitStartedNanos = System.nanoTime();
            }
        }
        if (parent != null) {
            parent.waitStarted();
        }
    }

    /** A wait at a gate ended. */
    void waitEnded() {
        synchronized (this) {
            if (waits > 0 && --waits == 0) {
                excludedNanos += System.nanoTime() - waitStartedNanos;
            }
        }
        if (parent != null) {
            parent.waitEnded();
        }
    }

    private synchronized boolean isWaiting() {
        return waits > 0;
    }

    private synchronized long excludedNanos() {
        return excludedNanos + (waits > 0 ? System.nanoTime() - waitStartedNanos : 0L);
    }

    private static void restore(ModelCallTimer previous) {
        if (previous == null) {
            CURRENT.remove();
        } else {
            CURRENT.set(previous);
        }
    }
}
