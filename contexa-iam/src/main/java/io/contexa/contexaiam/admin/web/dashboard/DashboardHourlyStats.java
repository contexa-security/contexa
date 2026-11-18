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
package io.contexa.contexaiam.admin.web.dashboard;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity.Status;
import io.contexa.contexaiam.admin.web.monitoring.service.DecisionRecordSealCheck;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.Scheduled;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.TreeSet;
import java.util.function.Supplier;

/**
 * The dashboard's hourly tables (plan step 9, N7 and N20), kept the way the Zero Trust console keeps its own
 * ({@code ZeroTrustHourlyStats}): every interval the current and the previous hour are rebuilt, and every hour an audit
 * record written late (the audit is written asynchronously) reached since the last pass; the first pass after a start
 * rebuilds the last 48 hours and then fills, a few hours a pass, the hours of the last 90 days that have no row yet.
 * <ul>
 *     <li>The refused requests of signed-in users (AUTHORIZATION_DENIED of the URL authorization), by resource and by
 *     user. They name users, so they are kept as long as the decision rows.</li>
 *     <li>The seal check of the decision records (VERIFIED, MISMATCH, UNVERIFIABLE counted by hour). A check reads the
 *     store up to three times, which is why no screen counts the period's records itself. A record changed after its
 *     hour was checked is found when the hour is checked again: the hours checked longest ago are checked again, a few
 *     thousand records a pass. The records that do not match are kept by ID beside the hour's counts (K92), so the
 *     security event log lists the records the dashboard counts.</li>
 * </ul>
 */
@Slf4j
public class DashboardHourlyStats {

    /** The dimension of the refusals counted by resource. */
    public static final String RESOURCE = "RESOURCE";
    /** The dimension of the refusals counted by user. */
    public static final String USER = "USER";

    /** The hours a first pass after a start rebuilds, so a gap while the application was down is filled. */
    static final int FIRST_RUN_HOURS = 48;
    /** How far back a first pass looks for hours that have no row yet: the longest period the dashboard reads. */
    static final int BACKFILL_DAYS = 90;
    /** How many hours without a row one pass fills. */
    static final int BACKFILL_HOURS_PER_PASS = 48;
    /** How many decision records one pass checks again, besides the hours it rebuilds. */
    static final int SEAL_BUDGET = 2_000;
    /** How many decision records are read at a time. */
    static final int SEAL_BATCH = 500;
    /** How many rows one delete statement of the retention removes, and the most statements of a run. */
    static final int PURGE_BATCH = 5_000;
    static final int PURGE_MAX_BATCHES = 200;

    /** The name a request without a sign-in is recorded under. */
    static final String ANONYMOUS = "anonymousUser";

    private static final String DENIED = """
            INSERT INTO ctxa_dashboard_denial_hourly (bucket_start, dimension, item, counted, computed_at)
            SELECT ?, '%s', %s, COUNT(*), ?
              FROM ctxa_audit_log a
             WHERE a.event_category = 'AUTHORIZATION_DENIED' AND a.timestamp >= ? AND a.timestamp < ?
               AND a.principal_name IS NOT NULL AND a.principal_name <> '' AND a.principal_name <> '%s'
             GROUP BY %s
            """;
    private static final String RESOURCE_ITEM = "LEFT(COALESCE(NULLIF(a.resource_identifier, ''), a.request_uri, ''), 512)";
    private static final String USER_ITEM = "LEFT(a.principal_name, 512)";
    private static final String DENIED_BY_RESOURCE = DENIED.formatted(RESOURCE, RESOURCE_ITEM, ANONYMOUS, RESOURCE_ITEM);
    private static final String DENIED_BY_USER = DENIED.formatted(USER, USER_ITEM, ANONYMOUS, USER_ITEM);

    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final AuditLogRepository auditLogRepository;
    private final DecisionRecordSealCheck sealCheck;
    private final SecurityZeroTrustProperties properties;
    private final Clock clock;
    private final Deque<Instant> denialBackfill = new ArrayDeque<>();
    private final Deque<Instant> sealBackfill = new ArrayDeque<>();
    private volatile Long lastAuditId;

    /**
     * @param auditLogRepository the decision records the seals are checked on; without it no seal is counted
     * @param sealCheck          the seal check of the security event log; without it no seal is counted
     * @param properties         the console's settings, whose retention the tables follow
     */
    public DashboardHourlyStats(Supplier<JdbcOperations> jdbcOperationsSupplier,
                                @Nullable AuditLogRepository auditLogRepository,
                                @Nullable DecisionRecordSealCheck sealCheck,
                                @Nullable SecurityZeroTrustProperties properties, @Nullable Clock clock) {
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.auditLogRepository = auditLogRepository;
        this.sealCheck = sealCheck;
        this.properties = properties != null ? properties : new SecurityZeroTrustProperties();
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    @Scheduled(scheduler = "contexaTaskScheduler",
            fixedDelayString = "${contexa.security.zerotrust.console.aggregation-interval-ms:60000}")
    @SchedulerLock(name = "dashboardHourlyStats", lockAtMostFor = "PT10M", lockAtLeastFor = "PT10S")
    public void rebuild() {
        rebuildOnce();
    }

    /** One pass; returns how many hours were rebuilt. */
    public int rebuildOnce() {
        JdbcOperations jdbc = jdbcOperationsSupplier.get();
        if (jdbc == null) {
            return 0;
        }
        Instant now = clock.instant();
        Instant current = now.truncatedTo(ChronoUnit.HOURS);
        try {
            Long newest = jdbc.queryForObject("SELECT MAX(id) FROM ctxa_audit_log", Long.class);
            long seen = newest != null ? newest : 0L;
            TreeSet<Instant> hours = new TreeSet<>();
            hours.add(current);
            hours.add(current.minus(Duration.ofHours(1)));
            if (lastAuditId == null) {
                for (int hour = 2; hour <= FIRST_RUN_HOURS; hour++) {
                    hours.add(current.minus(Duration.ofHours(hour)));
                }
                queueBackfill(jdbc, now, current.minus(Duration.ofHours(FIRST_RUN_HOURS)));
            } else if (seen > lastAuditId) {
                // An audit record written after its hour was rebuilt changes that hour, however old.
                jdbc.queryForList("""
                        SELECT DISTINCT date_trunc('hour', a.timestamp)
                          FROM ctxa_audit_log a
                         WHERE a.id > ? AND a.id <= ?
                           AND a.event_category IN ('AUTHORIZATION_DENIED', 'SECURITY_DECISION')
                        """, Timestamp.class, lastAuditId, seen).forEach(hour -> hours.add(hour.toInstant()));
            }
            for (int filled = 0; filled < BACKFILL_HOURS_PER_PASS && !denialBackfill.isEmpty(); filled++) {
                rebuildDenials(jdbc, denialBackfill.poll(), now);
            }
            long checked = 0;
            for (Instant hour : hours) {
                rebuildDenials(jdbc, hour, now);
                checked += rebuildSeals(jdbc, hour, now);
            }
            checkAgain(jdbc, now, checked);
            lastAuditId = seen;
            return hours.size();
        } catch (DataAccessException exception) {
            log.error("[DashboardHourlyStats] Rebuilding the dashboard's hourly tables failed", exception);
            return 0;
        }
    }

    /** The hours of the last 90 days with refusals or decision records and no row, before the first pass's hours. */
    private void queueBackfill(JdbcOperations jdbc, Instant now, Instant before) {
        Timestamp since = Timestamp.from(now.minus(Duration.ofDays(BACKFILL_DAYS)));
        Timestamp until = Timestamp.from(before);
        denialBackfill.clear();
        sealBackfill.clear();
        jdbc.queryForList("""
                SELECT DISTINCT date_trunc('hour', a.timestamp)
                  FROM ctxa_audit_log a
                 WHERE a.event_category = 'AUTHORIZATION_DENIED' AND a.timestamp >= ? AND a.timestamp < ?
                   AND NOT EXISTS (SELECT 1 FROM ctxa_dashboard_denial_hourly d
                                    WHERE d.bucket_start = date_trunc('hour', a.timestamp))
                """, Timestamp.class, since, until).forEach(hour -> denialBackfill.add(hour.toInstant()));
        if (sealCheck != null && auditLogRepository != null) {
            jdbc.queryForList("""
                    SELECT DISTINCT date_trunc('hour', a.timestamp)
                      FROM ctxa_audit_log a
                     WHERE a.event_category = 'SECURITY_DECISION' AND a.timestamp >= ? AND a.timestamp < ?
                       AND NOT EXISTS (SELECT 1 FROM ctxa_dashboard_seal_hourly s
                                        WHERE s.bucket_start = date_trunc('hour', a.timestamp))
                    """, Timestamp.class, since, until).forEach(hour -> sealBackfill.add(hour.toInstant()));
            // K92: an hour counted before its mismatched records were kept by ID is checked again, so the list of
            // them holds what the count says.
            jdbc.queryForList("""
                    SELECT s.bucket_start
                      FROM ctxa_dashboard_seal_hourly s
                     WHERE s.bucket_start >= ? AND s.bucket_start < ? AND s.mismatched > 0
                       AND s.mismatched <> (SELECT COUNT(*) FROM ctxa_dashboard_seal_mismatch m
                                             WHERE m.bucket_start = s.bucket_start)
                    """, Timestamp.class, since, until).forEach(hour -> sealBackfill.add(hour.toInstant()));
        }
    }

    /**
     * Checks again the hours without a row yet, then the hours checked longest ago, until the pass has checked its
     * budget of records.
     */
    private void checkAgain(JdbcOperations jdbc, Instant now, long alreadyChecked) {
        if (sealCheck == null || auditLogRepository == null) {
            return;
        }
        long checked = alreadyChecked;
        Timestamp oldest = Timestamp.from(now.minus(Duration.ofDays(BACKFILL_DAYS)));
        Timestamp before = Timestamp.from(now.minus(Duration.ofMinutes(1)));
        for (int round = 0; checked < SEAL_BUDGET && round < 24; round++) {
            Instant hour = sealBackfill.poll();
            if (hour == null) {
                List<Timestamp> stalest = jdbc.queryForList("""
                        SELECT s.bucket_start FROM ctxa_dashboard_seal_hourly s
                         WHERE s.bucket_start >= ? AND s.computed_at < ?
                         ORDER BY s.computed_at, s.bucket_start
                         LIMIT 1
                        """, Timestamp.class, oldest, before);
                if (stalest.isEmpty()) {
                    return;
                }
                hour = stalest.get(0).toInstant();
            }
            checked += rebuildSeals(jdbc, hour, now);
        }
    }

    /** Rebuilds one hour of the refusals from the audit log. */
    void rebuildDenials(JdbcOperations jdbc, Instant hour, Instant now) {
        Timestamp from = Timestamp.from(hour);
        Timestamp to = Timestamp.from(hour.plus(Duration.ofHours(1)));
        Timestamp at = Timestamp.from(now);
        jdbc.update("DELETE FROM ctxa_dashboard_denial_hourly WHERE bucket_start = ?", from);
        jdbc.update(DENIED_BY_RESOURCE, from, at, from, to);
        jdbc.update(DENIED_BY_USER, from, at, from, to);
    }

    /** Checks the seal of every decision record of the hour and keeps the counts; returns how many were checked. */
    long rebuildSeals(JdbcOperations jdbc, Instant hour, Instant now) {
        if (sealCheck == null || auditLogRepository == null) {
            return 0;
        }
        ZoneId zone = ZoneId.systemDefault();
        LocalDateTime from = LocalDateTime.ofInstant(hour, zone);
        LocalDateTime to = LocalDateTime.ofInstant(hour.plus(Duration.ofHours(1)), zone);
        long checked = 0;
        List<Long> mismatched = new ArrayList<>();
        long unverifiable = 0;
        long afterId = 0;
        while (true) {
            List<AuditLog> batch = auditLogRepository.findSealedBatch(DecisionRecordSealCheck.SEALED_CATEGORY, from, to,
                    afterId, PageRequest.of(0, SEAL_BATCH));
            for (AuditLog record : batch) {
                Status status = sealCheck.check(record);
                checked++;
                if (status == Status.MISMATCH) {
                    mismatched.add(record.getId());
                } else if (status == Status.UNVERIFIABLE) {
                    unverifiable++;
                }
                afterId = record.getId();
            }
            if (batch.size() < SEAL_BATCH) {
                break;
            }
        }
        Timestamp bucket = Timestamp.from(hour);
        Timestamp at = Timestamp.from(now);
        jdbc.update("DELETE FROM ctxa_dashboard_seal_hourly WHERE bucket_start = ?", bucket);
        jdbc.update("DELETE FROM ctxa_dashboard_seal_mismatch WHERE bucket_start = ?", bucket);
        if (checked > 0) {
            jdbc.update("""
                    INSERT INTO ctxa_dashboard_seal_hourly (bucket_start, checked, mismatched, unverifiable, computed_at)
                    VALUES (?, ?, ?, ?, ?)
                    """, bucket, checked, mismatched.size(), unverifiable, at);
        }
        if (!mismatched.isEmpty()) {
            // K92: the records themselves, under the hour they were counted in.
            jdbc.batchUpdate("""
                    INSERT INTO ctxa_dashboard_seal_mismatch (audit_id, bucket_start, computed_at) VALUES (?, ?, ?)
                    ON CONFLICT (audit_id) DO UPDATE SET bucket_start = EXCLUDED.bucket_start,
                                                         computed_at = EXCLUDED.computed_at
                    """, mismatched.stream().map(id -> new Object[]{id, bucket, at}).toList());
            log.warn("[DashboardHourlyStats] {} decision records of the hour {} do not match their seal",
                    mismatched.size(), hour);
        }
        return checked;
    }

    @Scheduled(scheduler = "contexaTaskScheduler", cron = "${contexa.security.zerotrust.console.retention-cron:0 17 3 * * *}")
    @SchedulerLock(name = "dashboardHourlyRetention", lockAtMostFor = "PT1H", lockAtLeastFor = "PT1M")
    public void purge() {
        purgeOnce();
    }

    /**
     * One retention pass: the refusals name users and go with the decision rows (the decision retention), the seal
     * counts and the mismatched records kept by ID name nobody and go with the aggregates (the aggregate retention).
     * Returns how many rows went.
     */
    public long purgeOnce() {
        JdbcOperations jdbc = jdbcOperationsSupplier.get();
        if (jdbc == null) {
            return 0;
        }
        SecurityZeroTrustProperties.Console console = properties.getConsole();
        Instant now = clock.instant();
        Timestamp decisionCutoff = Timestamp.from(now.minus(Duration.ofDays(Math.max(1, console.getDecisionRetentionDays()))));
        Timestamp aggregateCutoff = Timestamp.from(now.minus(Duration.ofDays(Math.max(1, console.getAggregateRetentionDays()))));
        long removed = 0;
        try {
            removed += batches(jdbc, """
                    DELETE FROM ctxa_dashboard_denial_hourly
                     WHERE ctid IN (SELECT ctid FROM ctxa_dashboard_denial_hourly WHERE bucket_start < ? LIMIT ?)
                    """, decisionCutoff);
            removed += batches(jdbc, """
                    DELETE FROM ctxa_dashboard_seal_hourly
                     WHERE ctid IN (SELECT ctid FROM ctxa_dashboard_seal_hourly WHERE bucket_start < ? LIMIT ?)
                    """, aggregateCutoff);
            removed += batches(jdbc, """
                    DELETE FROM ctxa_dashboard_seal_mismatch
                     WHERE ctid IN (SELECT ctid FROM ctxa_dashboard_seal_mismatch WHERE bucket_start < ? LIMIT ?)
                    """, aggregateCutoff);
        } catch (DataAccessException exception) {
            log.error("[DashboardHourlyStats] Retention stopped after {} rows", removed, exception);
            return removed;
        }
        if (removed > 0) {
            log.info("[DashboardHourlyStats] Removed {} dashboard rows (refusals before {}, seal counts before {})",
                    removed, decisionCutoff, aggregateCutoff);
        }
        return removed;
    }

    private static long batches(JdbcOperations jdbc, String sql, Timestamp cutoff) {
        long removed = 0;
        for (int batch = 0; batch < PURGE_MAX_BATCHES; batch++) {
            int count = jdbc.update(sql, cutoff, PURGE_BATCH);
            removed += count;
            if (count < PURGE_BATCH) {
                break;
            }
        }
        return removed;
    }
}
