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

import java.sql.Date;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.function.Supplier;

/**
 * The review queue's daily sample (console design 11.3): a number of the day's stopped decisions (a challenge, an
 * escalation or a block), drawn at random, waits for an administrator to judge it in the decision detail. Without a
 * ground truth in operation it is the one direct measure of whether the decisions are right. Test runs are not drawn
 * (G28), and a day is drawn once.
 */
@Slf4j
public class ZeroTrustReviewSampler {

    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final SecurityZeroTrustProperties properties;
    private final Clock clock;

    public ZeroTrustReviewSampler(Supplier<JdbcOperations> jdbcOperationsSupplier,
                                  SecurityZeroTrustProperties properties, Clock clock) {
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.properties = properties;
        this.clock = clock == null ? Clock.systemUTC() : clock;
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
        if (console == null || !console.isEnabled() || jdbc == null || day == null || console.getReviewDailySample() <= 0) {
            return 0;
        }
        try {
            Integer drawn = jdbc.queryForObject(
                    "SELECT COUNT(*) FROM ctxa_zt_review_queue WHERE sample_day = ?", Integer.class, Date.valueOf(day));
            int missing = console.getReviewDailySample() - (drawn == null ? 0 : drawn);
            if (missing <= 0) {
                return 0;
            }
            Timestamp from = Timestamp.from(day.atStartOfDay().toInstant(ZoneOffset.UTC));
            Timestamp to = Timestamp.from(day.plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC));
            int added = jdbc.update("""
                    INSERT INTO ctxa_zt_review_queue (observation_id, sample_day, sampled_at, review_status)
                    SELECT o.observation_id, ?, ?, 'PENDING'
                      FROM ctxa_ai_security_decision_observation o
                     WHERE o.created_at >= ? AND o.created_at < ?
                       AND o.final_action IN ('CHALLENGE', 'ESCALATE', 'BLOCK')
                       AND o.attempt_kind = 'FIRST'
                       AND o.test_run_id IS NULL
                       AND NOT EXISTS (SELECT 1 FROM ctxa_zt_review_queue q WHERE q.observation_id = o.observation_id)
                     ORDER BY random()
                     LIMIT ?
                    """, Date.valueOf(day), Timestamp.from(clock.instant()), from, to, missing);
            if (added > 0) {
                log.info("[ZeroTrustReviewSampler] {} stopped decisions of {} wait for review", added, day);
            }
            return added;
        }
        catch (DataAccessException exception) {
            log.error("[ZeroTrustReviewSampler] Sampling the decisions of {} failed", day, exception);
            return 0;
        }
    }
}
