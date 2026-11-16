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

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.scheduling.annotation.Scheduled;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Supplier;

/**
 * The retention of the console data (console design 7.6): a decision row, its reason codes, its outcomes and its review
 * entry are kept for the decision retention (90 days by default), the hourly tables for the aggregate retention (two
 * years). It replaces the AI monitor's restart, which deleted the whole table. Rows go in batches so a long table never
 * holds a long lock.
 */
@Slf4j
public class ZeroTrustConsoleRetention {

    /** How many rows one delete statement removes. */
    static final int BATCH = 5_000;
    /** The most batches one run deletes from a table; the next run goes on. */
    static final int MAX_BATCHES = 200;

    /**
     * K21: a row written before the fix keeps the LLM step's label ({@code RUNTIME_MODEL_SELECTION}) or nothing as its
     * mode; the Zero Trust mode it ran under is in its metadata. Rows within the decision retention are set from it, a
     * batch at a time, so the decision records' mode filter finds them.
     */
    static final String REPAIR_BOUNDARY = """
            UPDATE ctxa_ai_security_decision_observation
               SET decision_boundary_mode = CAST(metadata_json AS jsonb) ->> 'runtimeEnforcementMode'
             WHERE ctid IN (SELECT ctid FROM ctxa_ai_security_decision_observation
                             WHERE created_at >= ?
                               AND (decision_boundary_mode IS NULL OR decision_boundary_mode NOT IN ('SHADOW', 'ENFORCE'))
                               AND metadata_json LIKE '%"runtimeEnforcementMode"%'
                               AND CAST(metadata_json AS jsonb) ->> 'runtimeEnforcementMode' IN ('SHADOW', 'ENFORCE')
                             LIMIT ?)
            """;

    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final SecurityZeroTrustProperties properties;
    private final Clock clock;

    public ZeroTrustConsoleRetention(Supplier<JdbcOperations> jdbcOperationsSupplier,
                                     SecurityZeroTrustProperties properties, Clock clock) {
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.properties = properties;
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    @Scheduled(scheduler = "contexaTaskScheduler", cron = "${contexa.security.zerotrust.console.retention-cron:0 17 3 * * *}")
    @SchedulerLock(name = "zeroTrustConsoleRetention", lockAtMostFor = "PT2H", lockAtLeastFor = "PT1M")
    public void purge() {
        purgeOnce();
    }

    /** One retention pass; returns how many rows went. */
    public long purgeOnce() {
        SecurityZeroTrustProperties.Console console = properties.getConsole();
        JdbcOperations jdbc = jdbcOperationsSupplier.get();
        if (console == null || !console.isEnabled() || jdbc == null) {
            return 0;
        }
        Instant now = clock.instant();
        Timestamp decisionCutoff = Timestamp.from(now.minus(Duration.ofDays(Math.max(1, console.getDecisionRetentionDays()))));
        Timestamp aggregateCutoff = Timestamp.from(now.minus(Duration.ofDays(Math.max(1, console.getAggregateRetentionDays()))));
        long removed = 0;
        try {
            long repaired = batches(jdbc, REPAIR_BOUNDARY, decisionCutoff);
            if (repaired > 0) {
                log.info("[ZeroTrustConsoleRetention] Set the Zero Trust mode of {} decision rows from their metadata",
                        repaired);
            }
            removed += batches(jdbc, """
                    DELETE FROM ctxa_zt_decision_reason
                     WHERE ctid IN (SELECT ctid FROM ctxa_zt_decision_reason WHERE created_at < ? LIMIT ?)
                    """, decisionCutoff);
            removed += batches(jdbc, """
                    DELETE FROM ctxa_zt_decision_outcome
                     WHERE ctid IN (SELECT ctid FROM ctxa_zt_decision_outcome WHERE occurred_at < ? LIMIT ?)
                    """, decisionCutoff);
            removed += batches(jdbc, """
                    DELETE FROM ctxa_zt_review_queue
                     WHERE ctid IN (SELECT ctid FROM ctxa_zt_review_queue WHERE sampled_at < ? LIMIT ?)
                    """, decisionCutoff);
            removed += batches(jdbc, """
                    DELETE FROM ctxa_ai_security_decision_observation
                     WHERE ctid IN (SELECT ctid FROM ctxa_ai_security_decision_observation WHERE created_at < ? LIMIT ?)
                    """, decisionCutoff);
            // The ranked lists name users: they go with the decision rows.
            removed += batches(jdbc, """
                    DELETE FROM ctxa_zt_item_hourly
                     WHERE ctid IN (SELECT ctid FROM ctxa_zt_item_hourly WHERE bucket_start < ? LIMIT ?)
                    """, decisionCutoff);
            removed += batches(jdbc, """
                    DELETE FROM ctxa_zt_stats_hourly
                     WHERE ctid IN (SELECT ctid FROM ctxa_zt_stats_hourly WHERE bucket_start < ? LIMIT ?)
                    """, aggregateCutoff);
            removed += batches(jdbc, """
                    DELETE FROM ctxa_zt_coverage_hourly
                     WHERE ctid IN (SELECT ctid FROM ctxa_zt_coverage_hourly WHERE bucket_start < ? LIMIT ?)
                    """, aggregateCutoff);
            removed += batches(jdbc, """
                    DELETE FROM ctxa_zt_latency_hourly
                     WHERE ctid IN (SELECT ctid FROM ctxa_zt_latency_hourly WHERE bucket_start < ? LIMIT ?)
                    """, aggregateCutoff);
        }
        catch (DataAccessException exception) {
            log.error("[ZeroTrustConsoleRetention] Retention stopped after {} rows", removed, exception);
            return removed;
        }
        if (removed > 0) {
            log.info("[ZeroTrustConsoleRetention] Removed {} console rows (decisions before {}, aggregates before {})",
                    removed, decisionCutoff, aggregateCutoff);
        }
        return removed;
    }

    private static long batches(JdbcOperations jdbc, String sql, Timestamp cutoff) {
        long removed = 0;
        for (int batch = 0; batch < MAX_BATCHES; batch++) {
            int count = jdbc.update(sql, cutoff, BATCH);
            removed += count;
            if (count < BATCH) {
                break;
            }
        }
        return removed;
    }
}
