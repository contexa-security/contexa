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

import java.util.Locale;
import io.contexa.contexacore.autonomous.telemetry.SecurityEventTelemetryContext;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The gate of one model server (O-1). Every call to the server, a chat or an embedding, passes it:
 * <ul>
 *   <li>no more calls run at once than the server takes ({@code maxConcurrent}, 0 for no limit);</li>
 *   <li>calls go in in the order they came, embeddings before waiting chats, and a call that is in is never cut;</li>
 *   <li>a chat that is the first decision of a session ({@link ModelCallTimer#firstInLine()}) goes before the chats of
 *       sessions that have one, so filling the line with those keeps no one away from a first decision (Q-23);</li>
 *   <li>on a server that loads one model at a time ({@code oneModelAtATime}), a call for another model goes in when the
 *       calls of the loaded model are done, and the calls behind it wait, so that the switch is not starved;</li>
 *   <li>after a call met a rate limit or an overload ({@link Permit#overloaded()}) the server is closed for a while,
 *       longer at each signal in a row, and the calls wait in line until it opens again;</li>
 *   <li>a call made inside a call that is in ({@link Permit#scope(Callable)}: a tool or an advisor calling the same
 *       server again) goes in under the slot of the call it runs in, since waiting for a slot of its own would wait
 *       for the call that waits for it.</li>
 * </ul>
 * The wait is left out of the time limits of the waiting thread's {@link ModelCallTimer}, and it ends with a
 * {@link ModelServerBusyException} when the call cannot get in within its longest wait.
 */
public final class ModelServerGate {

    /** The back-off grows to at most this many times the first one (2 s, 4 s, 8 s, 12 s by default). */
    private static final int MAX_BACK_OFF_FACTOR = 6;
    /** The gates whose slot the work running on this thread holds, with how deep the scopes are. */
    private static final ThreadLocal<Map<ModelServerGate, Integer>> SCOPES =
            ThreadLocal.withInitial(IdentityHashMap::new);

    private final ModelServer server;
    private final int maxConcurrent;
    private final boolean oneModelAtATime;
    private final long firstBackOffNanos;

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition changed = lock.newCondition();
    private final ArrayDeque<Waiter> embeddings = new ArrayDeque<>();
    private final ArrayDeque<Waiter> firstChats = new ArrayDeque<>();
    private final ArrayDeque<Waiter> chats = new ArrayDeque<>();
    private final Map<String, Integer> runningByModel = new HashMap<>();
    private int running;
    private int overloadsInARow;
    private long closedUntilNanos;
    private boolean closed;

    public ModelServerGate(ModelServer server, int maxConcurrent, boolean oneModelAtATime, Duration firstBackOff) {
        this.server = server;
        this.maxConcurrent = Math.max(0, maxConcurrent);
        this.oneModelAtATime = oneModelAtATime;
        this.firstBackOffNanos = firstBackOff != null ? Math.max(0L, firstBackOff.toNanos()) : 0L;
    }

    public ModelServer server() {
        return server;
    }

    public int maxConcurrent() {
        return maxConcurrent;
    }

    public boolean oneModelAtATime() {
        return oneModelAtATime;
    }

    /** Enters with the timer bound to this thread. */
    public Permit enter(CallKind kind, String model, long maxWaitMs) throws InterruptedException {
        return enter(kind, model, maxWaitMs, ModelCallTimer.current());
    }

    /**
     * Waits for the call's turn and a free slot.
     *
     * @param model     the model the call asks for; calls of one model share a self-hosted server
     * @param maxWaitMs the longest the call waits
     * @param timer     the timer whose limits leave the wait out, or null
     * @throws ModelServerBusyException when the call cannot get in within {@code maxWaitMs}
     * @throws InterruptedException     when the waiting thread is interrupted; the call leaves the line
     */
    public Permit enter(CallKind kind, String model, long maxWaitMs, ModelCallTimer timer) throws InterruptedException {
        CallKind callKind = kind != null ? kind : CallKind.CHAT;
        Waiter waiter = new Waiter(callKind, model != null && !model.isBlank() ? model.trim() : callKind.name(),
                timer != null && timer.firstInLine());
        if (SCOPES.get().containsKey(this)) {
            return new Permit(waiter.model, 0L, true);
        }
        long started = System.nanoTime();
        long waitUntil = started + TimeUnit.MILLISECONDS.toNanos(Math.max(0L, maxWaitMs));
        boolean timerStopped = false;
        lock.lockInterruptibly();
        try {
            if (head() == null && canEnter(waiter, started)) {
                return admit(waiter, 0L);
            }
            lineOf(waiter).addLast(waiter);
            if (timer != null) {
                timer.waitStarted();
                timerStopped = true;
            }
            while (true) {
                long now = System.nanoTime();
                if (head() == waiter && canEnter(waiter, now)) {
                    lineOf(waiter).remove(waiter);
                    Permit permit = admit(waiter, now - started);
                    changed.signalAll();
                    return permit;
                }
                long left = waitUntil - now;
                if (left <= 0L) {
                    lineOf(waiter).remove(waiter);
                    changed.signalAll();
                    throw busy(callKind, now - started);
                }
                if (closed && closedUntilNanos > now) {
                    left = Math.min(left, closedUntilNanos - now);
                }
                try {
                    changed.awaitNanos(left);
                } catch (InterruptedException interrupted) {
                    lineOf(waiter).remove(waiter);
                    changed.signalAll();
                    throw interrupted;
                }
            }
        } finally {
            lock.unlock();
            if (timerStopped) {
                timer.waitEnded();
            }
            recordWait(callKind, System.nanoTime() - started);
        }
    }

    /** The calls in now. */
    public int running() {
        lock.lock();
        try {
            return running;
        } finally {
            lock.unlock();
        }
    }

    /** The calls waiting now. */
    public int waiting() {
        lock.lock();
        try {
            return linedUp();
        } finally {
            lock.unlock();
        }
    }

    private boolean canEnter(Waiter waiter, long now) {
        if (closed) {
            if (closedUntilNanos > now) {
                return false;
            }
            closed = false;
        }
        if (maxConcurrent > 0 && running >= maxConcurrent) {
            return false;
        }
        return !oneModelAtATime || running == 0 || runningByModel.containsKey(waiter.model);
    }

    private Waiter head() {
        Waiter embedding = embeddings.peekFirst();
        if (embedding != null) {
            return embedding;
        }
        Waiter firstChat = firstChats.peekFirst();
        return firstChat != null ? firstChat : chats.peekFirst();
    }

    private ArrayDeque<Waiter> lineOf(Waiter waiter) {
        if (waiter.kind == CallKind.EMBEDDING) {
            return embeddings;
        }
        return waiter.firstInLine ? firstChats : chats;
    }

    private int linedUp() {
        return embeddings.size() + firstChats.size() + chats.size();
    }

    private Permit admit(Waiter waiter, long waitedNanos) {
        running++;
        runningByModel.merge(waiter.model, 1, Integer::sum);
        return new Permit(waiter.model, TimeUnit.NANOSECONDS.toMillis(waitedNanos), false);
    }

    private void leave(Permit permit) {
        lock.lock();
        try {
            running = Math.max(0, running - 1);
            runningByModel.computeIfPresent(permit.model, (model, count) -> count > 1 ? count - 1 : null);
            if (!permit.overloaded) {
                overloadsInARow = 0;
            }
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    private void backOff() {
        if (firstBackOffNanos <= 0L) {
            return;
        }
        lock.lock();
        try {
            overloadsInARow++;
            long factor = Math.min(MAX_BACK_OFF_FACTOR, 1L << Math.min(30, overloadsInARow - 1));
            long until = System.nanoTime() + firstBackOffNanos * factor;
            if (!closed || until - closedUntilNanos > 0L) {
                closedUntilNanos = until;
            }
            closed = true;
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    private ModelServerBusyException busy(CallKind kind, long waitedNanos) {
        int waiting = linedUp();
        return new ModelServerBusyException(server.key(), "No free slot at model server " + server.key()
                + " for a " + kind.name().toLowerCase(Locale.ROOT) + " call within " + TimeUnit.NANOSECONDS.toMillis(waitedNanos)
                + "ms (" + running + " running, " + waiting + " waiting)");
    }

    private static void recordWait(CallKind kind, long waitedNanos) {
        long waitedMs = TimeUnit.NANOSECONDS.toMillis(waitedNanos);
        SecurityEventTelemetryContext.incrementBy(kind == CallKind.EMBEDDING ? "embeddingAcquireMs" : "chatAcquireMs",
                waitedMs);
    }

    /**
     * A call in line. Two waiters with the same kind, model and line are two calls: a class without an {@code equals},
     * so that a waiter leaving the line ({@code remove}) takes out itself and never an equal one ahead of it, which left
     * its own entry at the head with no thread behind it and kept every call behind it from going in.
     */
    private static final class Waiter {

        private final CallKind kind;
        private final String model;
        private final boolean firstInLine;

        private Waiter(CallKind kind, String model, boolean firstInLine) {
            this.kind = kind;
            this.model = model;
            this.firstInLine = firstInLine;
        }
    }

    /** A call that is in; closing it frees its slot. */
    public final class Permit implements AutoCloseable {

        private final String model;
        private final long waitedMillis;
        private final boolean nested;
        private final AtomicBoolean left = new AtomicBoolean();
        private volatile boolean overloaded;

        private Permit(String model, long waitedMillis, boolean nested) {
            this.model = model;
            this.waitedMillis = waitedMillis;
            this.nested = nested;
        }

        /** How long the call waited to get in. */
        public long waitedMillis() {
            return waitedMillis;
        }

        public ModelServer server() {
            return server;
        }

        /** The provider limited the rate or was overloaded: the server backs off before the next call goes in. */
        public void overloaded() {
            overloaded = true;
            backOff();
        }

        /** The call's work, run with this slot held, on whatever thread runs it: calls inside go in under it. */
        public <T> Callable<T> scope(Callable<T> work) {
            return () -> {
                Map<ModelServerGate, Integer> scopes = SCOPES.get();
                scopes.merge(ModelServerGate.this, 1, Integer::sum);
                try {
                    return work.call();
                } finally {
                    scopes.computeIfPresent(ModelServerGate.this, (gate, depth) -> depth > 1 ? depth - 1 : null);
                    if (scopes.isEmpty()) {
                        SCOPES.remove();
                    }
                }
            };
        }

        @Override
        public void close() {
            if (!nested && left.compareAndSet(false, true)) {
                leave(this);
            }
        }
    }
}
