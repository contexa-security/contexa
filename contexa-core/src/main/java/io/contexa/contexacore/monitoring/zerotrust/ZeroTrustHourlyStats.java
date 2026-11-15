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

import io.contexa.contexacommon.enums.ZeroTrustAction;
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
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.TreeSet;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * The hourly decision table the console reads (console design 7.4): one row per hour and per combination of the
 * dimensions the screens filter by, with the counts, the latency and wait buckets the p50 and p95 come from, the
 * token sums and the outcome counts. Every interval it rebuilds the current and the previous hour and every hour
 * whose decisions got an outcome since its last run, so a late outcome (a release days later) reaches its hour. It
 * also records the challenges nobody answered in time as expired. A decision is a first attempt that reached an
 * action (console design 5): a retry, a re-judgement, a timeout and a rejection are no decisions of their own, and a
 * test run is not counted (G28).
 */
@Slf4j
public class ZeroTrustHourlyStats {

    /** The hours a first run after a start rebuilds, so a gap while the application was down is filled. */
    static final int FIRST_RUN_HOURS = 48;

    /** The rows of an hour that are decisions: first attempts that reached an action, test runs aside. */
    private static final String DECIDED = """
            o.created_at >= ? AND o.created_at < ?
               AND o.attempt_kind = 'FIRST'
               AND o.final_action IN ('ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK')
               AND o.test_run_id IS NULL""";

    /**
     * Console design 5: a timed-out or rejected try whose request never got a decision is a technical failure, a
     * "no decision" of its own. It is kept under the action NO_DECISION, so it never
     * counts as a decision; its failure is kept as its cause.
     */
    private static final String NO_DECISION = """
            INSERT INTO ctxa_zt_stats_hourly (
                bucket_start, tenant_id, decision_boundary_mode, final_action, decision_source, decision_change_cause,
                decision_stage, most_likely_hypothesis, resource_class, actor_kind, enforcement_timing,
                prompt_bundle_version, model_id, decision_count, computed_at)
            SELECT ?, COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), 'NO_DECISION', '',
                   LEFT(COALESCE(o.failure_type, o.attempt_kind, ''), 32), '', '', COALESCE(o.resource_class, ''),
                   COALESCE(o.actor_kind, ''), COALESCE(o.enforcement_timing, ''), COALESCE(o.prompt_bundle_version, ''),
                   COALESCE(o.model_id, ''), COUNT(*), ?
              FROM ctxa_ai_security_decision_observation o
             WHERE o.created_at >= ? AND o.created_at < ?
               AND o.attempt_kind IN ('TIMEOUT', 'REJECTED')
               AND o.test_run_id IS NULL
               AND NOT EXISTS (SELECT 1 FROM ctxa_ai_security_decision_observation d
                                WHERE d.event_id = o.event_id AND d.attempt_kind = 'FIRST'
                                  AND d.final_action IN ('ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'))
             GROUP BY COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''),
                      LEFT(COALESCE(o.failure_type, o.attempt_kind, ''), 32), COALESCE(o.resource_class, ''),
                      COALESCE(o.actor_kind, ''), COALESCE(o.enforcement_timing, ''),
                      COALESCE(o.prompt_bundle_version, ''), COALESCE(o.model_id, '')
            """;

    /**
     * The lists the screens rank and the people they count (console design 6.1, 6.2, 6.3, 6.6): the decisions of each
     * user by action, the challenges each user passed, the stopped decisions of each resource, the first reason of
     * each decision, the facts the model did not know and the paths whose requests got no decision.
     */
    private static final String ITEM_USERS = """
            INSERT INTO ctxa_zt_item_hourly (bucket_start, tenant_id, decision_boundary_mode, dimension, item, detail,
                                             counted, computed_at)
            SELECT ?, COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), 'USER', LEFT(o.user_id, 512),
                   o.final_action, COUNT(*), ?
              FROM ctxa_ai_security_decision_observation o
             WHERE %s AND o.user_id IS NOT NULL
             GROUP BY COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), LEFT(o.user_id, 512),
                      o.final_action
            """.formatted(DECIDED);

    private static final String ITEM_PASSED = """
            INSERT INTO ctxa_zt_item_hourly (bucket_start, tenant_id, decision_boundary_mode, dimension, item, detail,
                                             counted, computed_at)
            SELECT ?, COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), 'USER_PASSED',
                   LEFT(o.user_id, 512), '', COUNT(DISTINCT o.observation_id), ?
              FROM ctxa_ai_security_decision_observation o
              JOIN ctxa_zt_decision_outcome d ON d.observation_id = o.observation_id
                                             AND d.outcome_kind = 'CHALLENGE_PASSED'
             WHERE %s AND o.user_id IS NOT NULL
             GROUP BY COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), LEFT(o.user_id, 512)
            """.formatted(DECIDED);

    private static final String ITEM_USER_BASELINES = """
            INSERT INTO ctxa_zt_item_hourly (bucket_start, tenant_id, decision_boundary_mode, dimension, item, detail,
                                             counted, computed_at)
            SELECT ?, COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), 'USER_BASELINE',
                   LEFT(o.user_id, 512), COALESCE(o.baseline_status, ''), COUNT(*), ?
              FROM ctxa_ai_security_decision_observation o
             WHERE %s AND o.user_id IS NOT NULL
             GROUP BY COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), LEFT(o.user_id, 512),
                      COALESCE(o.baseline_status, '')
            """.formatted(DECIDED);

    private static final String ITEM_USER_REASONS = """
            INSERT INTO ctxa_zt_item_hourly (bucket_start, tenant_id, decision_boundary_mode, dimension, item, detail,
                                             counted, computed_at)
            SELECT ?, COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), 'USER_REASON',
                   LEFT(o.user_id, 512), r.reason_code, COUNT(*), ?
              FROM ctxa_ai_security_decision_observation o
              JOIN ctxa_zt_decision_reason r ON r.observation_id = o.observation_id AND r.reason_rank = 1
             WHERE %s AND o.user_id IS NOT NULL AND o.final_action = 'CHALLENGE'
             GROUP BY COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), LEFT(o.user_id, 512),
                      r.reason_code
            """.formatted(DECIDED);

    private static final String ITEM_RESOURCES = """
            INSERT INTO ctxa_zt_item_hourly (bucket_start, tenant_id, decision_boundary_mode, dimension, item, detail,
                                             counted, computed_at)
            SELECT ?, COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), 'RESOURCE',
                   LEFT(COALESCE(NULLIF(o.resource_id, ''), o.request_path), 512), o.final_action, COUNT(*), ?
              FROM ctxa_ai_security_decision_observation o
             WHERE %s AND o.final_action IN ('CHALLENGE', 'ESCALATE', 'BLOCK')
               AND COALESCE(NULLIF(o.resource_id, ''), o.request_path) IS NOT NULL
             GROUP BY COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''),
                      LEFT(COALESCE(NULLIF(o.resource_id, ''), o.request_path), 512), o.final_action
            """.formatted(DECIDED);

    private static final String ITEM_FIRST_REASONS = """
            INSERT INTO ctxa_zt_item_hourly (bucket_start, tenant_id, decision_boundary_mode, dimension, item, detail,
                                             counted, computed_at)
            SELECT ?, COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), 'FIRST_REASON', r.reason_code,
                   o.final_action, COUNT(*), ?
              FROM ctxa_ai_security_decision_observation o
              JOIN ctxa_zt_decision_reason r ON r.observation_id = o.observation_id AND r.reason_rank = 1
             WHERE %s
             GROUP BY COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), r.reason_code, o.final_action
            """.formatted(DECIDED);

    private static final String ITEM_UNKNOWN_FACTS = """
            INSERT INTO ctxa_zt_item_hourly (bucket_start, tenant_id, decision_boundary_mode, dimension, item, detail,
                                             counted, computed_at)
            SELECT ?, COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), 'UNKNOWN_FACT',
                   LEFT(u.key, 512), LEFT(u.value, 64), COUNT(*), ?
              FROM ctxa_ai_security_decision_observation o
             CROSS JOIN LATERAL jsonb_each_text(CAST(o.decision_summary_json AS jsonb) -> 'unknown') u
             WHERE %s AND o.decision_summary_json IS NOT NULL
               AND jsonb_typeof(CAST(o.decision_summary_json AS jsonb) -> 'unknown') = 'object'
             GROUP BY COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), LEFT(u.key, 512),
                      LEFT(u.value, 64)
            """.formatted(DECIDED);

    /** Console plan 5-2 ①: the decisions by the provider and the model that answered them, as the AI monitor showed. */
    private static final String ITEM_PROVIDERS = """
            INSERT INTO ctxa_zt_item_hourly (bucket_start, tenant_id, decision_boundary_mode, dimension, item, detail,
                                             counted, computed_at)
            SELECT ?, COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), 'PROVIDER',
                   LEFT(COALESCE(NULLIF(o.model_provider, ''), 'UNKNOWN'), 512), LEFT(COALESCE(o.model_id, ''), 64),
                   COUNT(*), ?
              FROM ctxa_ai_security_decision_observation o
             WHERE %s
             GROUP BY COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''),
                      LEFT(COALESCE(NULLIF(o.model_provider, ''), 'UNKNOWN'), 512), LEFT(COALESCE(o.model_id, ''), 64)
            """.formatted(DECIDED);

    /** Console plan 5-2 ②: the decisions by what started their analysis (a protected method, an AuthZEN evaluation). */
    private static final String ITEM_TRIGGERS = """
            INSERT INTO ctxa_zt_item_hourly (bucket_start, tenant_id, decision_boundary_mode, dimension, item, detail,
                                             counted, computed_at)
            SELECT ?, COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), 'TRIGGER',
                   LEFT(COALESCE(NULLIF(o.trigger_source, ''), 'UNKNOWN'), 512), '', COUNT(*), ?
              FROM ctxa_ai_security_decision_observation o
             WHERE %s
             GROUP BY COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''),
                      LEFT(COALESCE(NULLIF(o.trigger_source, ''), 'UNKNOWN'), 512)
            """.formatted(DECIDED);

    private static final String ITEM_FAILED_PATHS = """
            INSERT INTO ctxa_zt_item_hourly (bucket_start, tenant_id, decision_boundary_mode, dimension, item, detail,
                                             counted, computed_at)
            SELECT ?, COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), 'FAILED_PATH',
                   LEFT(o.request_path, 512), LEFT(COALESCE(o.failure_type, o.attempt_kind, ''), 64), COUNT(*), ?
              FROM ctxa_ai_security_decision_observation o
             WHERE o.created_at >= ? AND o.created_at < ?
               AND o.attempt_kind IN ('TIMEOUT', 'REJECTED')
               AND o.test_run_id IS NULL
               AND o.request_path IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM ctxa_ai_security_decision_observation d
                                WHERE d.event_id = o.event_id AND d.attempt_kind = 'FIRST'
                                  AND d.final_action IN ('ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'))
             GROUP BY COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), LEFT(o.request_path, 512),
                      LEFT(COALESCE(o.failure_type, o.attempt_kind, ''), 64)
            """;

    /**
     * Console design 6.6: the time each stage of a decision took, in buckets an hour can be added to another with, so
     * the screen reads a median and a 95th percentile of any period from the buckets.
     */
    private static final String LATENCY = """
            INSERT INTO ctxa_zt_latency_hourly (
                bucket_start, tenant_id, decision_boundary_mode, stage, measured, sum_ms, le_100ms, le_250ms, le_500ms,
                le_1s, le_2s, le_5s, le_10s, le_30s, le_60s, gt_60s, computed_at)
            SELECT ?, s.tenant_id, s.boundary, s.stage, COUNT(*), SUM(s.ms),
                   SUM(CASE WHEN s.ms <= 100 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN s.ms > 100 AND s.ms <= 250 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN s.ms > 250 AND s.ms <= 500 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN s.ms > 500 AND s.ms <= 1000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN s.ms > 1000 AND s.ms <= 2000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN s.ms > 2000 AND s.ms <= 5000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN s.ms > 5000 AND s.ms <= 10000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN s.ms > 10000 AND s.ms <= 30000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN s.ms > 30000 AND s.ms <= 60000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN s.ms > 60000 THEN 1 ELSE 0 END),
                   ?
              FROM (SELECT COALESCE(o.tenant_id, '') AS tenant_id, COALESCE(o.decision_boundary_mode, '') AS boundary,
                           v.stage, v.ms
                      FROM ctxa_ai_security_decision_observation o
                     CROSS JOIN LATERAL (VALUES ('QUEUE', o.queue_wait_ms), ('PREPARE', o.prompt_build_ms),
                                                ('RAG', o.rag_vector_ms), ('MODEL', o.llm_latency_ms),
                                                ('PERSIST', o.persist_ms), ('TOTAL', o.total_analysis_ms),
                                                ('USER_WAIT', o.user_wait_ms)) AS v(stage, ms)
                     WHERE %s AND v.ms IS NOT NULL AND v.ms >= 0) s
             GROUP BY s.tenant_id, s.boundary, s.stage
            """.formatted(DECIDED);

    private static final String REBUILD = """
            INSERT INTO ctxa_zt_stats_hourly (
                bucket_start, tenant_id, decision_boundary_mode, final_action, decision_source, decision_change_cause,
                decision_stage, most_likely_hypothesis, resource_class, actor_kind, enforcement_timing,
                prompt_bundle_version, model_id, decision_count, protected_decision_count, baseline_established_count,
                baseline_provisional_count,
                baseline_none_count, environment_context_count, identity_context_count, scope_context_count,
                business_context_count, unknown_fact_sum, retried_count,
                latency_sum_ms, latency_le_1s, latency_le_2s, latency_le_5s, latency_le_10s, latency_le_30s,
                latency_le_60s, latency_le_90s, latency_gt_90s,
                user_wait_count, user_wait_sum_ms, user_wait_le_1s, user_wait_le_2s, user_wait_le_5s, user_wait_le_10s,
                user_wait_le_30s, user_wait_gt_30s,
                prompt_tokens_sum, cached_prompt_tokens_sum, output_tokens_sum, model_call_sum,
                challenge_passed_count, challenge_failed_count, challenge_expired_count, unblock_requested_count,
                admin_released_count, block_kept_count, evaluated_valid_count, evaluated_invalid_count, computed_at)
            SELECT ?,
                   COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), COALESCE(o.final_action, ''),
                   COALESCE(o.decision_source, ''), COALESCE(o.decision_change_cause, ''),
                   COALESCE(o.decision_stage, ''), COALESCE(o.most_likely_hypothesis, ''),
                   COALESCE(o.resource_class, ''), COALESCE(o.actor_kind, ''), COALESCE(o.enforcement_timing, ''),
                   COALESCE(o.prompt_bundle_version, ''), COALESCE(o.model_id, ''),
                   COUNT(*),
                   SUM(CASE WHEN o.trigger_source = 'PROTECTABLE' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.baseline_status = 'ESTABLISHED' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.baseline_status = 'PROVISIONAL' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.baseline_status = 'NONE' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.context_coverage_level = 'ENVIRONMENT_ONLY' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.context_coverage_level = 'IDENTITY_AWARE' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.context_coverage_level = 'SCOPE_AWARE' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.context_coverage_level = 'BUSINESS_AWARE' THEN 1 ELSE 0 END),
                   SUM(COALESCE(o.unknown_fact_count, 0)),
                   -- A corrective retry is a model call past one per layer the decision ran.
                   SUM(CASE WHEN COALESCE(o.model_call_count, 0)
                                 > (CASE WHEN o.decision_stage = 'LAYER2' THEN 2 ELSE 1 END) THEN 1 ELSE 0 END),
                   SUM(COALESCE(o.total_analysis_ms, 0)),
                   SUM(CASE WHEN o.total_analysis_ms <= 1000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.total_analysis_ms > 1000 AND o.total_analysis_ms <= 2000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.total_analysis_ms > 2000 AND o.total_analysis_ms <= 5000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.total_analysis_ms > 5000 AND o.total_analysis_ms <= 10000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.total_analysis_ms > 10000 AND o.total_analysis_ms <= 30000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.total_analysis_ms > 30000 AND o.total_analysis_ms <= 60000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.total_analysis_ms > 60000 AND o.total_analysis_ms <= 90000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.total_analysis_ms > 90000 THEN 1 ELSE 0 END),
                   COUNT(o.user_wait_ms),
                   SUM(COALESCE(o.user_wait_ms, 0)),
                   SUM(CASE WHEN o.user_wait_ms <= 1000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.user_wait_ms > 1000 AND o.user_wait_ms <= 2000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.user_wait_ms > 2000 AND o.user_wait_ms <= 5000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.user_wait_ms > 5000 AND o.user_wait_ms <= 10000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.user_wait_ms > 10000 AND o.user_wait_ms <= 30000 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN o.user_wait_ms > 30000 THEN 1 ELSE 0 END),
                   SUM(COALESCE(o.prompt_tokens, 0)), SUM(COALESCE(o.cached_prompt_tokens, 0)),
                   SUM(COALESCE(o.output_tokens, 0)), SUM(COALESCE(o.model_call_count, 0)),
                   SUM(COALESCE(r.passed, 0)), SUM(COALESCE(r.failed, 0)), SUM(COALESCE(r.expired, 0)),
                   SUM(COALESCE(r.unblock_requested, 0)), SUM(COALESCE(r.released, 0)), SUM(COALESCE(r.kept, 0)),
                   SUM(COALESCE(r.valid, 0)), SUM(COALESCE(r.invalid, 0)),
                   ?
              FROM ctxa_ai_security_decision_observation o
              LEFT JOIN (
                    SELECT d.observation_id,
                           MAX(CASE WHEN d.outcome_kind = 'CHALLENGE_PASSED' THEN 1 ELSE 0 END) AS passed,
                           MAX(CASE WHEN d.outcome_kind = 'CHALLENGE_FAILED' THEN 1 ELSE 0 END) AS failed,
                           MAX(CASE WHEN d.outcome_kind = 'CHALLENGE_EXPIRED' THEN 1 ELSE 0 END) AS expired,
                           MAX(CASE WHEN d.outcome_kind = 'UNBLOCK_REQUESTED' THEN 1 ELSE 0 END) AS unblock_requested,
                           MAX(CASE WHEN d.outcome_kind = 'ADMIN_RELEASED' THEN 1 ELSE 0 END) AS released,
                           MAX(CASE WHEN d.outcome_kind = 'BLOCK_KEPT' THEN 1 ELSE 0 END) AS kept,
                           MAX(CASE WHEN d.outcome_kind = 'EVALUATED_VALID' THEN 1 ELSE 0 END) AS valid,
                           MAX(CASE WHEN d.outcome_kind = 'EVALUATED_INVALID' THEN 1 ELSE 0 END) AS invalid
                      FROM ctxa_zt_decision_outcome d
                      JOIN ctxa_ai_security_decision_observation od ON od.observation_id = d.observation_id
                     WHERE od.created_at >= ? AND od.created_at < ?
                     GROUP BY d.observation_id) r ON r.observation_id = o.observation_id
             WHERE o.created_at >= ? AND o.created_at < ?
               AND o.attempt_kind = 'FIRST'
               AND o.final_action IN ('ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK')
               AND o.test_run_id IS NULL
             GROUP BY COALESCE(o.tenant_id, ''), COALESCE(o.decision_boundary_mode, ''), COALESCE(o.final_action, ''),
                      COALESCE(o.decision_source, ''), COALESCE(o.decision_change_cause, ''),
                      COALESCE(o.decision_stage, ''),
                      COALESCE(o.most_likely_hypothesis, ''), COALESCE(o.resource_class, ''),
                      COALESCE(o.actor_kind, ''), COALESCE(o.enforcement_timing, ''),
                      COALESCE(o.prompt_bundle_version, ''), COALESCE(o.model_id, '')
            """;

    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final SecurityZeroTrustProperties properties;
    private final ZeroTrustCoverageCounter coverageCounter;
    private final Clock clock;
    private volatile Instant lastRun;

    public ZeroTrustHourlyStats(Supplier<JdbcOperations> jdbcOperationsSupplier, SecurityZeroTrustProperties properties,
                                ZeroTrustCoverageCounter coverageCounter, Clock clock) {
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.properties = properties;
        this.coverageCounter = coverageCounter;
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /**
     * The coverage counts are this node's own, so every node writes them; the hourly decision table is rebuilt by one
     * node at a time under the lock.
     */
    @Scheduled(scheduler = "contexaTaskScheduler",
            fixedDelayString = "${contexa.security.zerotrust.console.aggregation-interval-ms:60000}")
    public void flushCoverage() {
        if (coverageCounter != null && enabled()) {
            coverageCounter.flush();
        }
    }

    @Scheduled(scheduler = "contexaTaskScheduler",
            fixedDelayString = "${contexa.security.zerotrust.console.aggregation-interval-ms:60000}")
    @SchedulerLock(name = "zeroTrustHourlyStats", lockAtMostFor = "PT10M", lockAtLeastFor = "PT10S")
    public void rebuild() {
        rebuildOnce();
    }

    /** One pass: the expired challenges, then the hours to rebuild; returns how many hours were rebuilt. */
    public int rebuildOnce() {
        JdbcOperations jdbc = jdbcOperationsSupplier.get();
        if (jdbc == null || !enabled()) {
            return 0;
        }
        Instant now = clock.instant();
        Instant since = lastRun != null ? lastRun : now.minus(Duration.ofHours(FIRST_RUN_HOURS));
        try {
            attachLateDecisions(jdbc, now);
            recordExpiredChallenges(jdbc, now);
            TreeSet<Instant> hours = new TreeSet<>();
            Instant current = now.truncatedTo(ChronoUnit.HOURS);
            hours.add(current);
            hours.add(current.minus(Duration.ofHours(1)));
            if (lastRun == null) {
                for (int hour = 2; hour <= FIRST_RUN_HOURS; hour++) {
                    hours.add(current.minus(Duration.ofHours(hour)));
                }
            }
            // A late outcome changes the hour of its decision, however old.
            List<Timestamp> late = jdbc.queryForList("""
                    SELECT DISTINCT date_trunc('hour', o.created_at)
                      FROM ctxa_zt_decision_outcome d
                      JOIN ctxa_ai_security_decision_observation o ON o.observation_id = d.observation_id
                     WHERE d.created_at >= ?
                    """, Timestamp.class, Timestamp.from(since.minus(Duration.ofMinutes(1))));
            late.forEach(hour -> hours.add(hour.toInstant()));
            for (Instant hour : hours) {
                rebuildHour(jdbc, hour, now);
            }
            lastRun = now;
            return hours.size();
        }
        catch (DataAccessException exception) {
            log.error("[ZeroTrustHourlyStats] Rebuilding the hourly decision table failed", exception);
            return 0;
        }
    }

    /** Rebuilds one hour of the table from the decision rows and their outcomes. */
    void rebuildHour(JdbcOperations jdbc, Instant hour, Instant now) {
        Timestamp from = Timestamp.from(hour);
        Timestamp to = Timestamp.from(hour.plus(Duration.ofHours(1)));
        Timestamp at = Timestamp.from(now);
        jdbc.update("DELETE FROM ctxa_zt_stats_hourly WHERE bucket_start = ?", from);
        jdbc.update("DELETE FROM ctxa_zt_item_hourly WHERE bucket_start = ?", from);
        jdbc.update("DELETE FROM ctxa_zt_latency_hourly WHERE bucket_start = ?", from);
        jdbc.update(REBUILD, from, at, from, to, from, to);
        jdbc.update(NO_DECISION, from, at, from, to);
        for (String items : List.of(ITEM_USERS, ITEM_PASSED, ITEM_USER_BASELINES, ITEM_USER_REASONS, ITEM_RESOURCES,
                ITEM_FIRST_REASONS, ITEM_UNKNOWN_FACTS, ITEM_PROVIDERS, ITEM_TRIGGERS, ITEM_FAILED_PATHS)) {
            jdbc.update(items, from, at, from, to);
        }
        jdbc.update(LATENCY, from, at, from, to);
    }

    /**
     * An outcome recorded before the decision row of its request was written (the row is written after the
     * enforcement) meets that row once it is there; the outcome's hour of record stays its own.
     */
    int attachLateDecisions(JdbcOperations jdbc, Instant now) {
        return jdbc.update("""
                UPDATE ctxa_zt_decision_outcome d
                   SET observation_id = (SELECT o.observation_id
                                           FROM ctxa_ai_security_decision_observation o
                                          WHERE o.request_id = d.request_id AND o.success = TRUE
                                          ORDER BY o.created_at DESC
                                          LIMIT 1)
                 WHERE d.observation_id IS NULL
                   AND d.request_id IS NOT NULL
                   AND d.created_at >= ?
                   AND EXISTS (SELECT 1 FROM ctxa_ai_security_decision_observation o
                                WHERE o.request_id = d.request_id AND o.success = TRUE)
                """, Timestamp.from(now.minus(Duration.ofDays(2))));
    }

    /**
     * A challenge without an answer after its time is expired or abandoned (console design 7.3): the account owner
     * neither passed nor failed it. Only challenges the request met count: a shadow challenge asks nobody.
     */
    int recordExpiredChallenges(JdbcOperations jdbc, Instant now) {
        Duration ttl = ZeroTrustAction.CHALLENGE.getDefaultTtl();
        Timestamp before = Timestamp.from(now.minus(ttl));
        Timestamp after = Timestamp.from(now.minus(ttl).minus(Duration.ofDays(2)));
        List<String[]> expired = jdbc.query("""
                SELECT o.observation_id, o.request_id, o.user_id, o.tenant_id
                  FROM ctxa_ai_security_decision_observation o
                 WHERE o.final_action = 'CHALLENGE'
                   AND o.attempt_kind = 'FIRST'
                   AND o.enforcement_result = 'APPLIED'
                   AND o.created_at < ? AND o.created_at >= ?
                   AND NOT EXISTS (SELECT 1 FROM ctxa_zt_decision_outcome d
                                    WHERE d.observation_id = o.observation_id
                                      AND d.outcome_kind IN ('CHALLENGE_PASSED', 'CHALLENGE_FAILED', 'CHALLENGE_EXPIRED'))
                """, (rs, n) -> new String[] {rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)},
                before, after);
        Timestamp at = Timestamp.from(now);
        for (String[] row : expired) {
            jdbc.update("""
                    INSERT INTO ctxa_zt_decision_outcome
                        (outcome_id, observation_id, request_id, user_id, tenant_id, outcome_kind, actor, occurred_at,
                         created_at)
                    VALUES (?, ?, ?, ?, ?, 'CHALLENGE_EXPIRED', 'contexa', ?, ?)
                    """, UUID.randomUUID().toString(), row[0], row[1], row[2], row[3], at, at);
        }
        return expired.size();
    }

    private boolean enabled() {
        SecurityZeroTrustProperties.Console console = properties != null ? properties.getConsole() : null;
        return console != null && console.isEnabled();
    }
}
