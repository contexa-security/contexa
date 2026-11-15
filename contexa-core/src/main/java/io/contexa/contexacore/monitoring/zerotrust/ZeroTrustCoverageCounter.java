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
package io.contexa.contexacore.monitoring.zerotrust;

import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcOperations;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.Supplier;

/**
 * The coverage counts of this node (console design 7.5): the protected calls, the calls a valid decision answered
 * without a new analysis, and the calls the analysis skipped, by reason. Nothing else counts these: an answer of a
 * decision in force and a skip in the line leave no decision row (G11). Each protected call ends in at most one count
 * of a kind other than {@link Kind#PROTECTED_CALL}, at the place that settles it; a call that reaches an analysis is
 * counted by its decision row instead.
 * <p>
 * The counts are the node's, over every tenant: the protected call is counted before its facts, the tenant among them,
 * are read, and reading them there would cost every call. Counting is in memory and costs a map lookup; every interval
 * the counts are added to the hourly coverage table under this node's id, so the nodes' counts add up. A count that
 * could not be written is kept for the next interval.
 */
@Slf4j
public class ZeroTrustCoverageCounter {

    /** The outcome of a call a valid decision answered without a new analysis (see {@link #settled}). */
    public static final String REUSED_OUTCOME = "REUSED";
    /** A second call of the same actor session while its analysis runs (asynchronous method). */
    public static final String RAPID_REENTRY = "RAPID_REENTRY_ACTOR_SESSION";
    /** A second call of the same actor session while its analysis runs (synchronous method). */
    public static final String RAPID_REENTRY_SYNC = "RAPID_REENTRY_ACTOR_SESSION_SYNC";
    /** The resource asks for a prompt-quality certificate it does not have; the call is refused before its analysis. */
    public static final String UNCERTIFIED_RESOURCE = "UNCERTIFIED_RESOURCE";
    /** The method policies or the delegator's authority refused the call; a refusal is not analysed. */
    public static final String POLICY_DENIED = "POLICY_DENIED";
    /** An agent's read passed while the first request of its kind is decided; that decision answers it. */
    public static final String PASSED_WITH_LEADING_REQUEST = "PASSED_WITH_LEADING_REQUEST";
    /** A person's call from a changed context past the decisions of a new context the window allows. */
    public static final String NEW_CONTEXT_LIMIT = "NEW_CONTEXT_LIMIT";
    /** A sensitive call from a changed context whose analysis was already asked for: it is told to come back. */
    public static final String CONTEXT_CHANGE_WAITS = "CONTEXT_CHANGE_WAITS";
    /** The session has an analysis of the same context in line or running. */
    public static final String SESSION_ALREADY_IN_LINE = "SESSION_ALREADY_IN_LINE";
    /** The user's share of the analysis line is taken. */
    public static final String PAST_THE_USERS_SHARE = "PAST_THE_USERS_SHARE";
    /** The line of analyses is at its limit. */
    public static final String PAST_THE_ANALYSIS_LINE = "PAST_THE_ANALYSIS_LINE";
    /** A synchronous call found no room for its analysis (the user's share or the analysis threads). */
    public static final String SYNC_ANALYSIS_REJECTED = "SYNC_ANALYSIS_REJECTED";
    /** An agent's call found no place in the decision flights. */
    public static final String ANALYSIS_BUSY = "ANALYSIS_BUSY";
    /** A decision of the same context waits for its audit record; it is not asked for again. */
    public static final String DECISION_AUDIT_PENDING = "DECISION_AUDIT_PENDING";
    /** The publisher's queue was full: the event never left the node. */
    public static final String PUBLISH_QUEUE_FULL = "PUBLISH_QUEUE_FULL";
    /** The analysis failed and was tried again as often as allowed. */
    public static final String DEFER_EXHAUSTED = "DEFER_EXHAUSTED";
    /** The batch the event was in failed to dispatch as often as allowed. */
    public static final String BATCH_REQUEUE_EXHAUSTED = "BATCH_REQUEUE_EXHAUSTED";

    /** What a count counts. */
    public enum Kind {
        /** A protected method call (and an AuthZEN evaluation) that asked for a decision. */
        PROTECTED_CALL,
        /** A call a valid decision answered without a new analysis. */
        REUSED,
        /** A call the analysis skipped; the reason says why. */
        SKIPPED
    }

    private record Key(Instant hour, Kind kind, String reason) {
    }

    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final String nodeId;
    private final Clock clock;
    private final Map<Key, LongAdder> counts = new ConcurrentHashMap<>();

    public ZeroTrustCoverageCounter(Supplier<JdbcOperations> jdbcOperationsSupplier, String nodeId, Clock clock) {
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.nodeId = nodeId == null ? "" : cut(nodeId.trim(), 160);
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /**
     * The node's id: the host name the platform gives (a container's or a pod's name), else the computer's name, else
     * {@code local}; characters a key does not take become an underscore.
     */
    public static String hostNodeId() {
        String host = System.getenv("HOSTNAME");
        if (host == null || host.isBlank()) {
            host = System.getenv("COMPUTERNAME");
        }
        if (host == null || host.isBlank()) {
            return "local";
        }
        return host.trim().replaceAll("[^A-Za-z0-9._-]", "_");
    }

    public void protectedCall() {
        count(Kind.PROTECTED_CALL, null);
    }

    public void reused() {
        count(Kind.REUSED, null);
    }

    public void skipped(String reason) {
        count(Kind.SKIPPED, reason);
    }

    /**
     * Counts how a call was settled without an analysis of its own: {@link #REUSED_OUTCOME} for a valid decision that
     * answered it, a skip reason otherwise; null counts nothing (the call reached an analysis, or is counted elsewhere).
     */
    public void settled(String outcome) {
        if (outcome == null) {
            return;
        }
        if (REUSED_OUTCOME.equals(outcome)) {
            reused();
        } else {
            skipped(outcome);
        }
    }

    private void count(Kind kind, String reason) {
        // The keys fit their columns, so no count of one key can stop the write of the others.
        Key key = new Key(clock.instant().truncatedTo(ChronoUnit.HOURS), kind,
                reason == null ? "" : cut(reason.trim(), 64));
        counts.computeIfAbsent(key, ignored -> new LongAdder()).increment();
    }

    /** Adds the counts so far to the hourly coverage table; returns how many rows were written. */
    public int flush() {
        JdbcOperations jdbc = jdbcOperationsSupplier.get();
        if (jdbc == null || counts.isEmpty()) {
            return 0;
        }
        int written = 0;
        int failed = 0;
        DataAccessException firstFailure = null;
        for (Map.Entry<Key, LongAdder> entry : counts.entrySet()) {
            long delta = entry.getValue().sumThenReset();
            if (delta == 0) {
                continue;
            }
            Key key = entry.getKey();
            try {
                jdbc.update("""
                        INSERT INTO ctxa_zt_coverage_hourly (bucket_start, tenant_id, node_id, counter_kind, reason, counted,
                                                             updated_at)
                        VALUES (?, '', ?, ?, ?, ?, ?)
                        ON CONFLICT (bucket_start, tenant_id, node_id, counter_kind, reason)
                        DO UPDATE SET counted = ctxa_zt_coverage_hourly.counted + EXCLUDED.counted,
                                      updated_at = EXCLUDED.updated_at
                        """, Timestamp.from(key.hour()), nodeId, key.kind().name(), key.reason(), delta,
                        Timestamp.from(clock.instant()));
                written++;
            }
            catch (DataAccessException exception) {
                entry.getValue().add(delta);
                failed++;
                if (firstFailure == null) {
                    firstFailure = exception;
                }
            }
        }
        if (firstFailure != null) {
            log.error("[ZeroTrustCoverageCounter] Writing {} coverage counts failed; they are kept for the next interval",
                    failed, firstFailure);
        }
        // An hour two hours back gets no new counts; its empty adders go.
        Instant stale = clock.instant().truncatedTo(ChronoUnit.HOURS).minus(2, ChronoUnit.HOURS);
        counts.entrySet().removeIf(entry -> entry.getKey().hour().isBefore(stale) && entry.getValue().sum() == 0);
        return written;
    }

    private static String cut(String value, int length) {
        return value.length() <= length ? value : value.substring(0, length);
    }

    /** The count so far of this node, not yet written (for tests and the operations screen). */
    public long pending(Kind kind) {
        return counts.entrySet().stream().filter(entry -> Objects.equals(entry.getKey().kind(), kind))
                .mapToLong(entry -> entry.getValue().sum()).sum();
    }

    /** The count so far of this node for one skip reason, not yet written. */
    public long pendingSkipped(String reason) {
        return counts.entrySet().stream()
                .filter(entry -> entry.getKey().kind() == Kind.SKIPPED && Objects.equals(entry.getKey().reason(), reason))
                .mapToLong(entry -> entry.getValue().sum()).sum();
    }
}
