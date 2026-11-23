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
package io.contexa.contexaiam.admin.promptquality.measure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.Nullable;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * The lease of the work that decides labelled cases or sealed decisions again (quality plan 3.3, 9): the measurements
 * of the prompt quality and the trials of prompt versions share it. One server at a time runs them, under the lock the
 * servers of the database share; the server that runs one keeps a heartbeat on its row, and a server that stops lets
 * both run out, so the server that takes the lock next resumes the work where it stopped. A cancellation is written to
 * the row, so the heartbeat of the server that runs the work reads it, whichever server it was given on.
 *
 * <p>The table of the work has the columns {@code id}, {@code status}, {@code runner_id}, {@code heartbeat_at},
 * {@code started_at} and {@code created_at}; its work waits as {@link #QUEUED}, runs as {@link #RUNNING} and is
 * cancelled as {@link #CANCELLED}.</p>
 */
public final class QualityRunLease {

    private static final Logger log = LoggerFactory.getLogger(QualityRunLease.class);

    public static final String QUEUED = "QUEUED";
    public static final String RUNNING = "RUNNING";
    public static final String CANCELLED = "CANCELLED";

    private static final Pattern NAME = Pattern.compile("[a-z_][a-z0-9_]*");

    /** What stops running work before its end: a cancellation, the lock lost, or a limit of the work itself. */
    public static final class Stop {

        private final AtomicBoolean cancelled = new AtomicBoolean();
        private final AtomicBoolean lockLost = new AtomicBoolean();
        private final AtomicBoolean halted = new AtomicBoolean();

        public void cancel() {
            cancelled.set(true);
        }

        public boolean cancelled() {
            return cancelled.get();
        }

        public void loseLock() {
            lockLost.set(true);
        }

        public boolean lockLost() {
            return lockLost.get();
        }

        /** Stops the work for a reason of its own, such as the call limit of a measurement. */
        public void halt() {
            halted.set(true);
        }

        public boolean halted() {
            return halted.get();
        }

        public boolean any() {
            return cancelled.get() || lockLost.get() || halted.get();
        }
    }

    private final Supplier<JdbcTemplate> jdbc;
    private final String table;
    private final String what;
    private final QualityMeasureLock lock;
    private final Duration heartbeat;
    private final Clock clock;
    private final String serverId;

    /**
     * @param table     the table of the work, a name of Contexa's schema
     * @param what      what the work is called in the log, such as "measurement"
     * @param lock      the lock the servers of the database share, or the lock of this server alone
     * @param heartbeat how often the running server renews the lock and the heartbeat
     * @param serverId  the name of this server in the heartbeat of the work it runs
     */
    public QualityRunLease(Supplier<JdbcTemplate> jdbc, String table, String what, QualityMeasureLock lock,
                           Duration heartbeat, @Nullable Clock clock, String serverId) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        if (table == null || !NAME.matcher(table).matches()) {
            throw new IllegalArgumentException("The table of the work is a name of the schema: " + table);
        }
        this.table = table;
        this.what = what != null && !what.isBlank() ? what : "work";
        this.lock = Objects.requireNonNull(lock, "lock");
        if (heartbeat == null || heartbeat.compareTo(Duration.ofMillis(100)) < 0) {
            throw new IllegalArgumentException("The heartbeat of the work is at least 100 ms");
        }
        this.heartbeat = heartbeat;
        this.clock = clock != null ? clock : Clock.systemUTC();
        this.serverId = serverId != null && !serverId.isBlank() ? serverId : "server";
    }

    public Duration heartbeat() {
        return heartbeat;
    }

    /** How long the lock and the heartbeat hold without a renewal: four heartbeats, so one missed renewal loses nothing. */
    public Duration lockFor() {
        return heartbeat.multipliedBy(4);
    }

    public String serverId() {
        return serverId;
    }

    /** The lock, held for {@link #lockFor()}, or empty when another server holds it. */
    public Optional<QualityMeasureLock.Held> acquire() {
        return lock.acquire(lockFor());
    }

    /** Whether work waits: queued, or running on a server whose heartbeat ran out. */
    public boolean anyWaiting() {
        Integer waiting = jdbc.get().queryForObject("select count(*) from " + table + " where status = ? or"
                + " (status = ? and (heartbeat_at is null or heartbeat_at < ?))", Integer.class, QUEUED, RUNNING,
                staleBefore());
        return waiting != null && waiting > 0;
    }

    /**
     * The work to run next, at most that many: the work this server left, or work whose server's heartbeat ran out,
     * before the work queued, the oldest first.
     *
     * @param select the select of the rows, ending with the table under the alias
     * @param alias  the alias of the table in the select
     */
    public <T> List<T> waiting(String select, String alias, RowMapper<T> row, int limit) {
        if (alias == null || !NAME.matcher(alias).matches()) {
            throw new IllegalArgumentException("The alias of the table is a plain name: " + alias);
        }
        String a = alias + ".";
        return jdbc.get().query(select + " where " + a + "status = ? and (" + a + "runner_id = ? or " + a
                + "heartbeat_at is null or " + a + "heartbeat_at < ?) or " + a + "status = ? order by case when " + a
                + "status = ? then 0 else 1 end, " + a + "created_at, " + a + "id limit ?", row, RUNNING, serverId,
                staleBefore(), QUEUED, RUNNING, Math.max(1, limit));
    }

    /** Takes the work for this server; false when it ended meanwhile. */
    public boolean claim(long id) {
        Timestamp now = Timestamp.from(clock.instant());
        return jdbc.get().update("update " + table + " set status = ?, runner_id = ?, heartbeat_at = ?, started_at ="
                + " coalesce(started_at, ?) where id = ? and status in (?, ?)", RUNNING, serverId, now, now, id,
                QUEUED, RUNNING) == 1;
    }

    /** The heartbeat of the work, at every heartbeat from one heartbeat on, until the returned future is cancelled. */
    public ScheduledFuture<?> keepAlive(ScheduledExecutorService timer, long id, QualityMeasureLock.Held held,
                                        Stop stop) {
        long every = heartbeat.toMillis();
        return timer.scheduleAtFixedRate(() -> beat(id, held, stop), every, every, TimeUnit.MILLISECONDS);
    }

    /** One heartbeat of running work: the lock and the row renewed, and a cancellation read. */
    public void beat(long id, QualityMeasureLock.Held held, Stop stop) {
        try {
            if (!held.extend(lockFor())) {
                stop.loseLock();
                log.warn("[QualityRunLease] The lock of {} {} ran out on {}; it stops here", what, id, serverId);
                return;
            }
            jdbc.get().update("update " + table + " set heartbeat_at = ? where id = ? and runner_id = ?",
                    Timestamp.from(clock.instant()), id, serverId);
            if (CANCELLED.equals(status(id))) {
                stop.cancel();
            }
        }
        catch (RuntimeException failure) {
            log.error("[QualityRunLease] The heartbeat of {} {} failed", what, id, failure);
        }
    }

    /** The state of the work as its row keeps it; null when there is no such row. */
    @Nullable
    public String status(long id) {
        return jdbc.get().query("select status from " + table + " where id = ?", (rs, row) -> rs.getString(1), id)
                .stream().findFirst().orElse(null);
    }

    private Timestamp staleBefore() {
        return Timestamp.from(clock.instant().minus(lockFor()));
    }
}
