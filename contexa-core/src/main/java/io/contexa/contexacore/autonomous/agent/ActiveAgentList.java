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

package io.contexa.contexacore.autonomous.agent;

import io.contexa.contexacommon.security.subject.AgentClientStatusUnavailableException;
import io.contexa.contexacore.autonomous.service.RestrictionRestorer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.SmartLifecycle;
import org.springframework.lang.Nullable;

import java.time.Duration;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;

/**
 * The approved agents in service, kept in memory, so that a request is read without waiting for the agent registry (and
 * the database behind it): who the account or the client of a request is, as {@link AgentRegistry#findByClientId} would
 * say, worked out from what {@link AgentRegistry#approvals} holds.
 * <p>
 * A change made in this JVM through the registry is applied at once, on the thread that made it, and the registry is read
 * again in the background to settle it. A change another JVM made to a shared store is found by reading the registry again
 * every few seconds, so it shows within that time. The list is read once before the web server takes a request, for a
 * short time only; what goes wrong never stops the application. While the list has not been read, or the registry has not
 * answered for longer than the list may go on answering from what it last read, the answer is that the registry cannot be
 * read ({@link AgentClientStatusUnavailableException}), as a lookup that fails says: a failure never reads as "no agent".
 * <p>
 * The list holds at most {@link #LIMIT} registrations. A registry that holds more cannot be kept in memory, which is said
 * as a failure to read it, never as a list that leaves agents out.
 */
@Slf4j
public class ActiveAgentList implements SmartLifecycle {

    /** Before the web server starts, as the restrictions are brought back. */
    public static final int PHASE = RestrictionRestorer.PHASE;

    /** The most registrations that decide the approved agents (see {@link AgentRegistry#approvals}) the list keeps. */
    public static final int LIMIT = 20_000;

    /** How often the registry is read again for the changes another JVM made. */
    static final Duration REFRESH_INTERVAL = Duration.ofSeconds(5);

    /** How long after its last reading the list answers when the registry does not: three readings. */
    static final Duration STALE_AFTER = Duration.ofSeconds(15);

    /** How long the start waits for the first reading before it goes on and leaves the rest to the background. */
    static final Duration FIRST_READING_WAIT = Duration.ofSeconds(5);

    private static final long REPORT_INTERVAL_NANOS = TimeUnit.MINUTES.toNanos(1);
    private static final String THREAD = "contexa-agent-list";

    private final AgentRegistry registry;
    private final LongSupplier nanoClock;
    private final Duration refreshInterval;
    private final Duration staleAfter;
    private final Duration firstReadingWait;
    private final int limit;

    private final Object lock = new Object();
    /** Every reading and every change takes a number; a reading that began before a change is not kept. Guarded by the lock. */
    private long issued;
    private long installed;
    private boolean reportedOnce;
    private long reportedAt;
    private boolean listening;
    private volatile Snapshot snapshot;
    private final AtomicBoolean settlePending = new AtomicBoolean();

    private volatile boolean running;
    private volatile ScheduledThreadPoolExecutor executor;

    public ActiveAgentList(AgentRegistry registry) {
        this(registry, System::nanoTime, REFRESH_INTERVAL, STALE_AFTER, FIRST_READING_WAIT, LIMIT);
    }

    ActiveAgentList(AgentRegistry registry, LongSupplier nanoClock, Duration refreshInterval, Duration staleAfter,
                    Duration firstReadingWait, int limit) {
        if (registry == null) {
            throw new IllegalArgumentException("An agent registry is required");
        }
        this.registry = registry;
        this.nanoClock = nanoClock;
        this.refreshInterval = refreshInterval;
        this.staleAfter = staleAfter;
        this.firstReadingWait = firstReadingWait;
        this.limit = limit;
    }

    /**
     * The identifier of the approved agent in service that the client is, as {@link AgentRegistry#findByClientId} names
     * it, or empty when the client is not one. It never waits for the registry.
     *
     * @throws AgentClientStatusUnavailableException when the list has not been read, or the registry has not answered
     *                                               for too long
     */
    public Optional<String> activeAgent(@Nullable String tenantId, String clientId) {
        Snapshot current = snapshot;
        if (current == null) {
            throw new AgentClientStatusUnavailableException("The approved agents have not been read from the registry");
        }
        if (nanoClock.getAsLong() - current.readAt > staleAfter.toNanos()) {
            throw new AgentClientStatusUnavailableException("The approved agents were last read from the registry too long ago");
        }
        return current.answer(tenantId, clientId);
    }

    /** Reads the registry now. What fails is reported and leaves the list as it was. */
    public void refresh() {
        long ticket;
        synchronized (lock) {
            ticket = ++issued;
        }
        long startedAt = nanoClock.getAsLong();
        Snapshot read;
        try {
            read = Snapshot.of(registry.approvals(limit), startedAt);
        } catch (RuntimeException failed) {
            reportFailure(failed);
            return;
        }
        synchronized (lock) {
            if (ticket > installed) {
                installed = ticket;
                snapshot = read;
            }
        }
    }

    /** A change made in this JVM: applied to the list at once, and the registry is read again to settle it. */
    private void changed(AgentApproval change) {
        synchronized (lock) {
            installed = ++issued;
            Snapshot current = snapshot;
            if (current != null) {
                snapshot = current.with(change);
            }
        }
        ScheduledThreadPoolExecutor own = executor;
        if (!running || own == null || !settlePending.compareAndSet(false, true)) {
            return;
        }
        try {
            own.execute(() -> {
                settlePending.set(false);
                refresh();
            });
        } catch (RejectedExecutionException stopped) {
            settlePending.set(false);
        }
    }

    private void reportFailure(RuntimeException failed) {
        long now = nanoClock.getAsLong();
        boolean due;
        synchronized (lock) {
            due = !reportedOnce || now - reportedAt >= REPORT_INTERVAL_NANOS;
            if (due) {
                reportedOnce = true;
                reportedAt = now;
            }
        }
        if (due) {
            log.error("The approved agents could not be read from the agent registry; once the list read last is {} old, "
                    + "an account is read as a person and the tokens of an agent's client are refused until the registry answers",
                    staleAfter, failed);
        }
    }

    @Override
    public void start() {
        if (running) {
            return;
        }
        running = true;
        ScheduledThreadPoolExecutor own = new ScheduledThreadPoolExecutor(1, task -> {
            Thread thread = new Thread(task, THREAD);
            thread.setDaemon(true);
            return thread;
        });
        own.setRemoveOnCancelPolicy(true);
        executor = own;
        synchronized (lock) {
            if (!listening) {
                listening = true;
                registry.onApprovalChange(this::changed);
            }
        }
        Future<?> first = own.submit(this::refresh);
        try {
            first.get(firstReadingWait.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException slow) {
            log.error("The approved agents were not read from the agent registry within {}: the application goes on starting; "
                    + "until they are read an account is read as a person and the tokens of an agent's client are refused",
                    firstReadingWait);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (ExecutionException unexpected) {
            log.error("The approved agents could not be read from the agent registry", unexpected.getCause());
        }
        own.scheduleWithFixedDelay(this::refresh, refreshInterval.toMillis(), refreshInterval.toMillis(),
                TimeUnit.MILLISECONDS);
    }

    @Override
    public void stop() {
        running = false;
        ScheduledThreadPoolExecutor own = executor;
        if (own != null) {
            own.shutdownNow();
        }
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    @Override
    public int getPhase() {
        return PHASE;
    }

    private record Key(String tenantKey, String name) {
    }

    /** What was read, and the answer for every client and agent identifier it names. Never changed once built. */
    private static final class Snapshot {

        private final Map<Key, AgentApproval> rows;
        private final Map<Key, String> answers;
        private final long readAt;

        private Snapshot(Map<Key, AgentApproval> rows, long readAt) {
            this.rows = rows;
            this.answers = answersOf(rows.values());
            this.readAt = readAt;
        }

        static Snapshot of(Collection<AgentApproval> approvals, long readAt) {
            Map<Key, AgentApproval> rows = new HashMap<>();
            approvals.forEach(approval -> rows.put(keyOf(approval), approval));
            return new Snapshot(rows, readAt);
        }

        /** The same reading with one agent's approval changed; it is no fresher than it was. */
        Snapshot with(AgentApproval change) {
            Map<Key, AgentApproval> changed = new HashMap<>(rows);
            if (change.gone()) {
                changed.remove(keyOf(change));
            } else {
                changed.put(keyOf(change), change);
            }
            return new Snapshot(changed, readAt);
        }

        /** As {@link AgentRegistry#findByClientId} chooses, then as the directory filters what it chose. */
        Optional<String> answer(@Nullable String tenantId, String clientId) {
            if (AgentRegistrations.blank(clientId)) {
                return Optional.empty();
            }
            return Optional.ofNullable(answers.get(new Key(AgentRegistrations.tenantKey(tenantId), clientId.trim())));
        }

        private static Key keyOf(AgentApproval approval) {
            return new Key(AgentRegistrations.tenantKey(approval.tenantId()), approval.agentId().trim());
        }

        /**
         * For each tenant and each name some registration has as its client or its identifier: the registration whose
         * client it is (the first by identifier), else the one whose identifier it is; it answers only when it is
         * approved and in service. A registration that is not in service still takes the client from one that is.
         */
        private static Map<Key, String> answersOf(Collection<AgentApproval> approvals) {
            Map<Key, AgentApproval> ofClient = new HashMap<>();
            Map<Key, AgentApproval> ofIdentifier = new HashMap<>();
            for (AgentApproval approval : approvals) {
                String tenantKey = AgentRegistrations.tenantKey(approval.tenantId());
                ofIdentifier.put(new Key(tenantKey, approval.agentId().trim()), approval);
                if (!AgentRegistrations.blank(approval.clientId())) {
                    ofClient.merge(new Key(tenantKey, approval.clientId().trim()), approval,
                            (first, second) -> first.agentId().compareTo(second.agentId()) <= 0 ? first : second);
                }
            }
            Map<Key, String> answers = new HashMap<>();
            ofIdentifier.forEach((key, approval) -> {
                AgentApproval chosen = ofClient.getOrDefault(key, approval);
                if (chosen.inService()) {
                    answers.put(key, chosen.agentId());
                }
            });
            ofClient.forEach((key, chosen) -> {
                if (!ofIdentifier.containsKey(key) && chosen.inService()) {
                    answers.put(key, chosen.agentId());
                }
            });
            return Map.copyOf(answers);
        }
    }
}
