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

import io.contexa.contexacore.monitoring.ai.DecisionRiskSignals;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.scheduling.annotation.Scheduled;

import java.sql.Date;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

/**
 * The review queue's daily sample (console design 11.3, quality plan 3.6): the decisions of a day an administrator is
 * asked to judge in the decision detail. Without a ground truth in operation it is the one direct measure of whether
 * the decisions are right. Test runs are not drawn (G28), and a decision waits in the queue once.
 *
 * <ol>
 * <li>The stopped decisions (a challenge, an escalation or a block), drawn at random, up to the daily number; a day
 * left short is drawn up to it again.</li>
 * <li>The allowed decisions by risk, up to their number: those of the day with a sign that they may be misses
 * ({@link DecisionRiskSignals}, the signs the sealing of allowed decisions chooses by), and the allowed decisions of a
 * user blocked in the day that no administrator released or judged wrong, looking back the set days from the block.
 * The ones before a block come first, then the ones with more signs; a random draw orders the rest.</li>
 * <li>The allowed decisions of the day without a sign, at random, up to their number: they fill the number of the
 * ordinary cases. A random sample of allowed decisions hardly ever finds a miss, so it is not the way to find one.</li>
 * </ol>
 *
 * The allowed decisions of a day are drawn once. While the sealed evidence capture runs, a decision is drawn only when
 * it is sealed, so that a decision an administrator judged can be replayed and made a case of; without the capture the
 * decisions are drawn as they are.
 */
@Slf4j
public class ZeroTrustReviewSampler {

    /** Why a decision of the daily sample waits in the review queue (K17 adds the rule an answer broke). */
    public static final String SAMPLE = "SAMPLE";

    /** The days looked back from a block for the allowed decisions of its user, by default. */
    public static final int DEFAULT_BLOCKED_LOOKBACK_DAYS = 7;

    /** The unknown decision facts from which an allowed decision is risky when nothing else is set. */
    private static final int DEFAULT_UNKNOWN_FACT_THRESHOLD = 3;

    private static final String STOPPED_ACTIONS = "('CHALLENGE', 'ESCALATE', 'BLOCK')";

    /** A decision of a person: a first attempt that is no test run. */
    private static final String FIRST_DECISION = "o.attempt_kind = 'FIRST' AND o.test_run_id IS NULL";

    /** The decision row is sealed: its package is in the store, sealed. */
    private static final String SEALED = "EXISTS (SELECT 1 FROM ctxa_sealed_evidence_package p"
            + " WHERE p.idempotency_key = o.idempotency_key AND p.seal_state = 'SEALED')";

    private static final String NOT_QUEUED = "NOT EXISTS (SELECT 1 FROM ctxa_zt_review_queue q"
            + " WHERE q.observation_id = o.observation_id)";

    /**
     * The users blocked in the day, with the time of their last block there: a first decision that blocked, which no
     * administrator released or judged wrong. Its parameters are the start and the end of the day.
     */
    private static final String BLOCKED = """
            WITH blocked AS (
                SELECT b.user_id, COALESCE(b.tenant_id, '') AS tenant, MAX(b.created_at) AS last_block
                  FROM ctxa_ai_security_decision_observation b
                 WHERE b.final_action = 'BLOCK' AND b.attempt_kind = 'FIRST' AND b.test_run_id IS NULL
                   AND b.user_id IS NOT NULL AND b.created_at >= ? AND b.created_at < ?
                   AND NOT EXISTS (SELECT 1 FROM ctxa_zt_decision_outcome d
                                    WHERE d.observation_id = b.observation_id
                                      AND d.outcome_kind IN ('ADMIN_RELEASED', 'EVALUATED_INVALID'))
                 GROUP BY b.user_id, COALESCE(b.tenant_id, ''))
            """;

    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final SecurityZeroTrustProperties properties;
    private final Clock clock;
    private final int unknownFactThreshold;
    private final BooleanSupplier sealedOnly;

    /** A sampler that does not know whether the decisions are sealed: it draws them as they are. */
    public ZeroTrustReviewSampler(Supplier<JdbcOperations> jdbcOperationsSupplier,
                                  SecurityZeroTrustProperties properties, Clock clock) {
        this(jdbcOperationsSupplier, properties, clock, DEFAULT_UNKNOWN_FACT_THRESHOLD, () -> false);
    }

    /**
     * @param unknownFactThreshold the unknown decision facts from which an allowed decision is risky: the threshold the
     *                             sealing of allowed decisions uses
     * @param sealedOnly           whether the sealed evidence capture runs, so that only sealed decisions are drawn
     */
    public ZeroTrustReviewSampler(Supplier<JdbcOperations> jdbcOperationsSupplier,
                                  SecurityZeroTrustProperties properties, Clock clock, int unknownFactThreshold,
                                  BooleanSupplier sealedOnly) {
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.properties = properties;
        this.clock = clock == null ? Clock.systemUTC() : clock;
        this.unknownFactThreshold = Math.max(1, unknownFactThreshold);
        this.sealedOnly = sealedOnly != null ? sealedOnly : () -> false;
    }

    @Scheduled(scheduler = "contexaTaskScheduler", cron = "${contexa.security.zerotrust.console.review-cron:0 7 0 * * *}",
            zone = "UTC")
    @SchedulerLock(name = "zeroTrustReviewSampler", lockAtMostFor = "PT30M", lockAtLeastFor = "PT1M")
    public void sampleYesterday() {
        sample(LocalDate.now(clock.withZone(ZoneOffset.UTC)).minusDays(1));
    }

    /** Draws the sample of one UTC day; returns how many decisions joined the queue. */
    public int sample(LocalDate day) {
        SecurityZeroTrustProperties.Console console = properties.getConsole();
        JdbcOperations jdbc = jdbcOperationsSupplier.get();
        if (console == null || !console.isEnabled() || jdbc == null || day == null) {
            return 0;
        }
        try {
            boolean sealed = sealedOnly.getAsBoolean();
            Timestamp from = Timestamp.from(day.atStartOfDay().toInstant(ZoneOffset.UTC));
            Timestamp to = Timestamp.from(day.plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC));
            int stopped = stopped(jdbc, console, day, from, to, sealed);
            int risky = 0;
            int ordinary = 0;
            if (drawn(jdbc, day, "o.final_action = 'ALLOW'") == 0) {
                Timestamp lookback = Timestamp.from(day.minusDays(Math.max(0, console.getReviewBlockedLookbackDays()))
                        .atStartOfDay().toInstant(ZoneOffset.UTC));
                risky = risky(jdbc, console, day, from, to, lookback, sealed);
                ordinary = ordinary(jdbc, console, day, from, to, sealed);
            }
            int added = stopped + risky + ordinary;
            if (added > 0) {
                log.info("[ZeroTrustReviewSampler] Decisions of {} wait for review: stopped={}, allowedByRisk={},"
                        + " allowedAtRandom={}, sealedOnly={}", day, stopped, risky, ordinary, sealed);
            }
            return added;
        }
        catch (DataAccessException exception) {
            log.error("[ZeroTrustReviewSampler] Sampling the decisions of {} failed", day, exception);
            return 0;
        }
    }

    /** How many decisions of the day's sample whose row meets the condition wait or waited in the queue. */
    private static int drawn(JdbcOperations jdbc, LocalDate day, String condition) {
        Integer drawn = jdbc.queryForObject("SELECT COUNT(*) FROM ctxa_zt_review_queue q"
                + " JOIN ctxa_ai_security_decision_observation o ON o.observation_id = q.observation_id"
                + " WHERE q.sample_day = ? AND q.review_reason = '" + SAMPLE + "' AND " + condition,
                Integer.class, Date.valueOf(day));
        return drawn == null ? 0 : drawn;
    }

    /** The stopped decisions of the day at random, up to the daily number; K17: a broken rule's entry is no part. */
    private int stopped(JdbcOperations jdbc, SecurityZeroTrustProperties.Console console, LocalDate day,
                        Timestamp from, Timestamp to, boolean sealed) {
        int missing = console.getReviewDailySample() - drawn(jdbc, day, "o.final_action IN " + STOPPED_ACTIONS);
        if (missing <= 0) {
            return 0;
        }
        return jdbc.update("""
                INSERT INTO ctxa_zt_review_queue (observation_id, sample_day, sampled_at, review_status, review_reason)
                SELECT o.observation_id, ?, ?, 'PENDING', 'SAMPLE'
                  FROM ctxa_ai_security_decision_observation o
                 WHERE o.created_at >= ? AND o.created_at < ?
                   AND o.final_action IN %s
                   AND %s
                   AND %s
                   AND %s
                 ORDER BY random()
                 LIMIT ?
                """.formatted(STOPPED_ACTIONS, FIRST_DECISION, NOT_QUEUED, sealed ? SEALED : "TRUE"),
                Date.valueOf(day), Timestamp.from(clock.instant()), from, to, missing);
    }

    /**
     * The allowed decisions by risk: those of the day with a sign, and those of a user blocked in the day, from the
     * lookback to the user's last block of the day.
     */
    private int risky(JdbcOperations jdbc, SecurityZeroTrustProperties.Console console, LocalDate day,
                      Timestamp from, Timestamp to, Timestamp lookback, boolean sealed) {
        if (console.getReviewRiskSample() <= 0) {
            return 0;
        }
        return jdbc.update(BLOCKED + """
                INSERT INTO ctxa_zt_review_queue (observation_id, sample_day, sampled_at, review_status, review_reason)
                SELECT c.observation_id, ?, ?, 'PENDING', 'SAMPLE'
                  FROM (SELECT o.observation_id, o.created_at,
                               CASE WHEN k.last_block IS NOT NULL AND o.created_at < k.last_block THEN 1 ELSE 0 END
                                   AS later_blocked,
                               %s AS signals
                          FROM ctxa_ai_security_decision_observation o
                          LEFT JOIN blocked k ON k.user_id = o.user_id AND k.tenant = COALESCE(o.tenant_id, '')
                         WHERE o.final_action = 'ALLOW'
                           AND %s
                           AND ((o.created_at >= ? AND o.created_at < ?)
                                OR (k.last_block IS NOT NULL AND o.created_at >= ? AND o.created_at < k.last_block))
                           AND %s
                           AND %s) c
                 WHERE c.later_blocked = 1 OR (c.signals > 0 AND c.created_at >= ?)
                 ORDER BY c.later_blocked DESC, c.signals DESC, random()
                 LIMIT ?
                """.formatted(DecisionRiskSignals.sqlCount("o", unknownFactThreshold), FIRST_DECISION, NOT_QUEUED,
                sealed ? SEALED : "TRUE"),
                from, to, Date.valueOf(day), Timestamp.from(clock.instant()), from, to, lookback, from,
                console.getReviewRiskSample());
    }

    /** The allowed decisions of the day without a sign and not before a block of their user, at random. */
    private int ordinary(JdbcOperations jdbc, SecurityZeroTrustProperties.Console console, LocalDate day,
                         Timestamp from, Timestamp to, boolean sealed) {
        if (console.getReviewAllowedSample() <= 0) {
            return 0;
        }
        return jdbc.update(BLOCKED + """
                INSERT INTO ctxa_zt_review_queue (observation_id, sample_day, sampled_at, review_status, review_reason)
                SELECT o.observation_id, ?, ?, 'PENDING', 'SAMPLE'
                  FROM ctxa_ai_security_decision_observation o
                  LEFT JOIN blocked k ON k.user_id = o.user_id AND k.tenant = COALESCE(o.tenant_id, '')
                 WHERE o.created_at >= ? AND o.created_at < ?
                   AND o.final_action = 'ALLOW'
                   AND NOT %s
                   AND (k.last_block IS NULL OR o.created_at >= k.last_block)
                   AND %s
                   AND %s
                   AND %s
                 ORDER BY random()
                 LIMIT ?
                """.formatted(DecisionRiskSignals.sqlCondition("o", unknownFactThreshold), FIRST_DECISION,
                NOT_QUEUED, sealed ? SEALED : "TRUE"),
                from, to, Date.valueOf(day), Timestamp.from(clock.instant()), from, to,
                console.getReviewAllowedSample());
    }
}
