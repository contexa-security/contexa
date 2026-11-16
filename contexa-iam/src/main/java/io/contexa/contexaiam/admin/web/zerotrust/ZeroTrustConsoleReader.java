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
package io.contexa.contexaiam.admin.web.zerotrust;

import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.PastWindow;
import org.springframework.jdbc.core.JdbcOperations;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Supplier;

/**
 * Reads the console's hourly tables (console design 7.4, 7.5): the screens read these and nothing else, so a period of
 * millions of decisions is read from a few thousand rows. Every query takes the period's hours and, when the screen is
 * filtered by one, the tenant.
 */
final class ZeroTrustConsoleReader {

    /** One group of the hourly decision table, summed over the period. */
    record StatsRow(String mode, String action, String source, String cause, String stage, String hypothesis,
                    String resourceClass, String actor, String timing, String bundle, String model, long decisions,
                    long protectedDecisions, long established, long provisional, long none, long environment, long identity, long scope,
                    long business, long unknownFacts, long retried, long latencySum, long promptTokens,
                    long cachedTokens, long outputTokens, long modelCalls, long passed, long failed, long expired,
                    long unblockRequested, long released, long kept, long valid, long invalid, Instant first,
                    Instant last) {

        boolean decision() {
            return !ZeroTrustConsoleService.NO_DECISION.equals(action);
        }
    }

    /** One item of a ranked list and one of its details, summed over the period. */
    record ItemRow(String item, String detail, long counted) {
    }

    /** A stage's latency buckets, summed over the period. */
    record LatencyRow(String stage, long measured, long sumMs, long[] buckets) {
    }

    /** One day, action, source and cause of the trend. */
    record DayRow(LocalDate day, String action, String source, String cause, long decisions, long established,
                  long passed, long tokens, long protectedDecisions) {
    }

    private final Supplier<JdbcOperations> jdbc;

    ZeroTrustConsoleReader(Supplier<JdbcOperations> jdbc) {
        this.jdbc = jdbc == null ? () -> null : jdbc;
    }

    JdbcOperations jdbc() {
        return jdbc.get();
    }

    List<StatsRow> stats(ZeroTrustConsoleRange range, String tenant) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return List.of();
        }
        List<Object> args = new ArrayList<>(List.of(range.fromHour(), range.toTimestamp()));
        String tenantClause = tenantClause(tenant, args);
        return operations.query("""
                SELECT decision_boundary_mode, final_action, decision_source, decision_change_cause, decision_stage,
                       most_likely_hypothesis, resource_class, actor_kind, enforcement_timing, prompt_bundle_version,
                       model_id, SUM(decision_count), SUM(protected_decision_count), SUM(baseline_established_count),
                       SUM(baseline_provisional_count),
                       SUM(baseline_none_count), SUM(environment_context_count), SUM(identity_context_count),
                       SUM(scope_context_count), SUM(business_context_count), SUM(unknown_fact_sum), SUM(retried_count),
                       SUM(latency_sum_ms), SUM(prompt_tokens_sum), SUM(cached_prompt_tokens_sum), SUM(output_tokens_sum),
                       SUM(model_call_sum), SUM(challenge_passed_count), SUM(challenge_failed_count),
                       SUM(challenge_expired_count), SUM(unblock_requested_count), SUM(admin_released_count),
                       SUM(block_kept_count), SUM(evaluated_valid_count), SUM(evaluated_invalid_count),
                       MIN(bucket_start), MAX(bucket_start)
                  FROM ctxa_zt_stats_hourly
                 WHERE bucket_start >= ? AND bucket_start < ?""" + tenantClause + """

                 GROUP BY decision_boundary_mode, final_action, decision_source, decision_change_cause, decision_stage,
                          most_likely_hypothesis, resource_class, actor_kind, enforcement_timing, prompt_bundle_version,
                          model_id
                """, (rs, row) -> new StatsRow(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8), rs.getString(9), rs.getString(10),
                rs.getString(11), rs.getLong(12), rs.getLong(13), rs.getLong(14), rs.getLong(15), rs.getLong(16),
                rs.getLong(17), rs.getLong(18), rs.getLong(19), rs.getLong(20), rs.getLong(21), rs.getLong(22),
                rs.getLong(23), rs.getLong(24), rs.getLong(25), rs.getLong(26), rs.getLong(27), rs.getLong(28),
                rs.getLong(29), rs.getLong(30), rs.getLong(31), rs.getLong(32), rs.getLong(33), rs.getLong(34),
                rs.getLong(35), instant(rs, 36), instant(rs, 37)), args.toArray());
    }

    /** The coverage counts of the period, by kind and reason; the nodes' counts over every tenant. */
    Map<String, Long> coverage(ZeroTrustConsoleRange range) {
        JdbcOperations operations = jdbc.get();
        Map<String, Long> counts = new LinkedHashMap<>();
        if (operations == null) {
            return counts;
        }
        operations.query("""
                SELECT counter_kind, reason, SUM(counted)
                  FROM ctxa_zt_coverage_hourly
                 WHERE bucket_start >= ? AND bucket_start < ?
                 GROUP BY counter_kind, reason
                """, rs -> {
            String reason = rs.getString(2);
            counts.merge(rs.getString(1) + (reason == null || reason.isEmpty() ? "" : ":" + reason), rs.getLong(3),
                    Long::sum);
        }, range.fromHour(), range.toTimestamp());
        return counts;
    }

    /** Every item and detail of a dimension in the period. */
    List<ItemRow> items(ZeroTrustConsoleRange range, String tenant, String mode, String dimension) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return List.of();
        }
        List<Object> args = new ArrayList<>(List.of(dimension, range.fromHour(), range.toTimestamp()));
        String clauses = tenantClause(tenant, args) + modeClause(mode, args);
        return operations.query("""
                SELECT item, detail, SUM(counted)
                  FROM ctxa_zt_item_hourly
                 WHERE dimension = ? AND bucket_start >= ? AND bucket_start < ?""" + clauses + """

                 GROUP BY item, detail
                """, (rs, row) -> new ItemRow(rs.getString(1), rs.getString(2), rs.getLong(3)), args.toArray());
    }

    /** The items of a dimension counted most often in the period, for the details given (all when none). */
    List<ItemRow> top(ZeroTrustConsoleRange range, String tenant, String mode, String dimension, List<String> details,
                      int limit) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return List.of();
        }
        List<Object> args = new ArrayList<>(List.of(dimension, range.fromHour(), range.toTimestamp()));
        StringBuilder clauses = new StringBuilder(tenantClause(tenant, args)).append(modeClause(mode, args));
        if (details != null && !details.isEmpty()) {
            clauses.append(" AND detail IN (").append(String.join(", ", details.stream().map(d -> "?").toList()))
                    .append(")");
            args.addAll(details);
        }
        args.add(limit);
        return operations.query("""
                SELECT item, '' AS detail, SUM(counted) AS total
                  FROM ctxa_zt_item_hourly
                 WHERE dimension = ? AND bucket_start >= ? AND bucket_start < ?""" + clauses + """

                 GROUP BY item
                 ORDER BY total DESC, item
                 LIMIT ?
                """, (rs, row) -> new ItemRow(rs.getString(1), rs.getString(2), rs.getLong(3)), args.toArray());
    }

    /** The distinct items of a dimension in the period (the users judged, for the user dimension). */
    long distinct(ZeroTrustConsoleRange range, String tenant, String mode, String dimension, List<String> details) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return 0;
        }
        List<Object> args = new ArrayList<>(List.of(dimension, range.fromHour(), range.toTimestamp()));
        StringBuilder clauses = new StringBuilder(tenantClause(tenant, args)).append(modeClause(mode, args));
        if (details != null && !details.isEmpty()) {
            clauses.append(" AND detail IN (").append(String.join(", ", details.stream().map(d -> "?").toList()))
                    .append(")");
            args.addAll(details);
        }
        Long count = operations.queryForObject("""
                SELECT COUNT(DISTINCT item)
                  FROM ctxa_zt_item_hourly
                 WHERE dimension = ? AND bucket_start >= ? AND bucket_start < ?""" + clauses, Long.class,
                args.toArray());
        return count == null ? 0 : count;
    }

    /** The users whose latest decision in the period had an established baseline. */
    long usersWithLatestBaseline(ZeroTrustConsoleRange range, String tenant, String status) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return 0;
        }
        List<Object> args = new ArrayList<>(List.of(range.fromHour(), range.toTimestamp()));
        String tenantClause = tenantClause(tenant, args);
        args.add(status);
        Long count = operations.queryForObject("""
                SELECT COUNT(*)
                  FROM (SELECT DISTINCT ON (item) item, detail
                          FROM ctxa_zt_item_hourly
                         WHERE dimension = 'USER_BASELINE' AND bucket_start >= ? AND bucket_start < ?""" + tenantClause
                + """

                         ORDER BY item, bucket_start DESC, counted DESC) latest
                 WHERE detail = ?
                """, Long.class, args.toArray());
        return count == null ? 0 : count;
    }

    List<LatencyRow> latency(ZeroTrustConsoleRange range, String tenant, String mode) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return List.of();
        }
        List<Object> args = new ArrayList<>(List.of(range.fromHour(), range.toTimestamp()));
        String clauses = tenantClause(tenant, args) + modeClause(mode, args);
        return operations.query("""
                SELECT stage, SUM(measured), SUM(sum_ms), SUM(le_100ms), SUM(le_250ms), SUM(le_500ms), SUM(le_1s),
                       SUM(le_2s), SUM(le_5s), SUM(le_10s), SUM(le_30s), SUM(le_60s), SUM(gt_60s)
                  FROM ctxa_zt_latency_hourly
                 WHERE bucket_start >= ? AND bucket_start < ?""" + clauses + """

                 GROUP BY stage
                """, (rs, row) -> {
            long[] buckets = new long[10];
            for (int i = 0; i < buckets.length; i++) {
                buckets[i] = rs.getLong(4 + i);
            }
            return new LatencyRow(rs.getString(1), rs.getLong(2), rs.getLong(3), buckets);
        }, args.toArray());
    }

    List<DayRow> days(ZeroTrustConsoleRange range, String tenant) {
        return days(range, tenant, null);
    }

    List<DayRow> days(ZeroTrustConsoleRange range, String tenant, String mode) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return List.of();
        }
        List<Object> args = new ArrayList<>(List.of(range.fromHour(), range.toTimestamp()));
        String tenantClause = tenantClause(tenant, args) + modeClause(mode, args);
        return operations.query("""
                SELECT CAST(date_trunc('day', bucket_start) AS DATE), final_action, decision_source,
                       decision_change_cause, SUM(decision_count), SUM(baseline_established_count),
                       SUM(challenge_passed_count), SUM(prompt_tokens_sum + output_tokens_sum),
                       SUM(protected_decision_count)
                  FROM ctxa_zt_stats_hourly
                 WHERE bucket_start >= ? AND bucket_start < ?""" + tenantClause + """

                 GROUP BY 1, 2, 3, 4
                 ORDER BY 1
                """, (rs, row) -> new DayRow(rs.getDate(1).toLocalDate(), rs.getString(2), rs.getString(3),
                rs.getString(4), rs.getLong(5), rs.getLong(6), rs.getLong(7), rs.getLong(8), rs.getLong(9)),
                args.toArray());
    }

    /** The coverage counts of each day, by kind; the nodes' counts over every tenant. */
    Map<LocalDate, Map<String, Long>> coverageDays(ZeroTrustConsoleRange range) {
        JdbcOperations operations = jdbc.get();
        Map<LocalDate, Map<String, Long>> days = new LinkedHashMap<>();
        if (operations == null) {
            return days;
        }
        operations.query("""
                SELECT CAST(date_trunc('day', bucket_start) AS DATE), counter_kind, SUM(counted)
                  FROM ctxa_zt_coverage_hourly
                 WHERE bucket_start >= ? AND bucket_start < ?
                 GROUP BY 1, 2
                """, rs -> {
            days.computeIfAbsent(rs.getDate(1).toLocalDate(), ignored -> new LinkedHashMap<>())
                    .merge(rs.getString(2), rs.getLong(3), Long::sum);
        }, range.fromHour(), range.toTimestamp());
        return days;
    }

    /** One stage's latency buckets of each day. */
    Map<LocalDate, long[]> latencyDays(ZeroTrustConsoleRange range, String tenant, String stage) {
        JdbcOperations operations = jdbc.get();
        Map<LocalDate, long[]> days = new LinkedHashMap<>();
        if (operations == null) {
            return days;
        }
        List<Object> args = new ArrayList<>(List.of(stage, range.fromHour(), range.toTimestamp()));
        String tenantClause = tenantClause(tenant, args);
        operations.query("""
                SELECT CAST(date_trunc('day', bucket_start) AS DATE), SUM(le_100ms), SUM(le_250ms), SUM(le_500ms),
                       SUM(le_1s), SUM(le_2s), SUM(le_5s), SUM(le_10s), SUM(le_30s), SUM(le_60s), SUM(gt_60s)
                  FROM ctxa_zt_latency_hourly
                 WHERE stage = ? AND bucket_start >= ? AND bucket_start < ?""" + tenantClause + """

                 GROUP BY 1
                """, rs -> {
            long[] buckets = new long[10];
            for (int i = 0; i < buckets.length; i++) {
                buckets[i] = rs.getLong(2 + i);
            }
            days.put(rs.getDate(1).toLocalDate(), buckets);
        }, args.toArray());
        return days;
    }

    /** The stopped decisions by ISO weekday (1 to 7) and four-hour band (0 to 5) of their hour. */
    List<long[]> stoppedByWeekdayAndBand(ZeroTrustConsoleRange range, String tenant) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return List.of();
        }
        List<Object> args = new ArrayList<>(List.of(range.fromHour(), range.toTimestamp()));
        String tenantClause = tenantClause(tenant, args);
        return operations.query("""
                SELECT CAST(EXTRACT(ISODOW FROM bucket_start) AS INTEGER),
                       CAST(FLOOR(EXTRACT(HOUR FROM bucket_start) / 4) AS INTEGER), SUM(decision_count)
                  FROM ctxa_zt_stats_hourly
                 WHERE bucket_start >= ? AND bucket_start < ?
                   AND final_action IN ('CHALLENGE', 'ESCALATE', 'BLOCK')""" + tenantClause + """

                 GROUP BY 1, 2
                """, (rs, row) -> new long[] {rs.getInt(1), rs.getInt(2), rs.getLong(3)}, args.toArray());
    }

    /** The decisions and, over every tenant, the protected calls of each hour. */
    Map<Instant, long[]> hours(ZeroTrustConsoleRange range, String tenant) {
        JdbcOperations operations = jdbc.get();
        Map<Instant, long[]> hours = new TreeMap<>();
        if (operations == null) {
            return hours;
        }
        List<Object> args = new ArrayList<>(List.of(range.fromHour(), range.toTimestamp()));
        String tenantClause = tenantClause(tenant, args);
        operations.query("""
                SELECT bucket_start, SUM(decision_count)
                  FROM ctxa_zt_stats_hourly
                 WHERE bucket_start >= ? AND bucket_start < ? AND final_action <> 'NO_DECISION'""" + tenantClause + """

                 GROUP BY 1
                """, rs -> {
            hours.computeIfAbsent(rs.getTimestamp(1).toInstant(), ignored -> new long[] {0, -1})[0] = rs.getLong(2);
        }, args.toArray());
        if (tenant == null) {
            operations.query("""
                    SELECT bucket_start, SUM(counted)
                      FROM ctxa_zt_coverage_hourly
                     WHERE bucket_start >= ? AND bucket_start < ? AND counter_kind = 'PROTECTED_CALL'
                     GROUP BY 1
                    """, rs -> {
                hours.computeIfAbsent(rs.getTimestamp(1).toInstant(), ignored -> new long[] {0, -1})[1] = rs.getLong(2);
            }, range.fromHour(), range.toTimestamp());
        }
        return hours;
    }

    /** When the hourly decision table was last brought up to date, or null. */
    Instant lastComputed() {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return null;
        }
        Timestamp last = operations.queryForObject("SELECT MAX(computed_at) FROM ctxa_zt_stats_hourly", Timestamp.class);
        return last == null ? null : last.toInstant();
    }

    /** The evaluations an administrator found invalid in the period, by reason. */
    Map<String, Long> invalidReasons(ZeroTrustConsoleRange range, String tenant) {
        JdbcOperations operations = jdbc.get();
        Map<String, Long> reasons = new LinkedHashMap<>();
        if (operations == null) {
            return reasons;
        }
        List<Object> args = new ArrayList<>(List.of(range.fromTimestamp(), range.toTimestamp()));
        String tenantClause = tenantClause(tenant, args);
        operations.query("""
                SELECT COALESCE(evaluation_reason, 'OTHER'), COUNT(*)
                  FROM ctxa_zt_decision_outcome
                 WHERE outcome_kind = 'EVALUATED_INVALID' AND occurred_at >= ? AND occurred_at < ?""" + tenantClause
                + """

                 GROUP BY 1
                """, rs -> {
            reasons.put(rs.getString(1), rs.getLong(2));
        }, args.toArray());
        return reasons;
    }

    /** The median time from a block to its release by an administrator, in hours; null for no release. */
    Double releaseMedianHours(ZeroTrustConsoleRange range, String tenant) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return null;
        }
        List<Object> args = new ArrayList<>(List.of(range.fromTimestamp(), range.toTimestamp()));
        String tenantClause = tenant == null ? "" : " AND d.tenant_id = ?";
        if (tenant != null) {
            args.add(tenant);
        }
        Double seconds = operations.queryForObject("""
                SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (d.occurred_at - o.created_at)))
                  FROM ctxa_zt_decision_outcome d
                  JOIN ctxa_ai_security_decision_observation o ON o.observation_id = d.observation_id
                 WHERE d.outcome_kind = 'ADMIN_RELEASED' AND d.occurred_at >= ? AND d.occurred_at < ?""" + tenantClause,
                Double.class, args.toArray());
        return seconds == null ? null : seconds / 3600.0;
    }

    long reviewPending() {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return 0;
        }
        Long count = operations.queryForObject(
                "SELECT COUNT(*) FROM ctxa_zt_review_queue WHERE review_status = 'PENDING'", Long.class);
        return count == null ? 0 : count;
    }

    /** The mode changes an operator made, latest first (console design 7.6). */
    List<String[]> modeChanges(int limit) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return List.of();
        }
        return operations.query("""
                SELECT timestamp, principal_name, decision, details
                  FROM ctxa_audit_log
                 WHERE event_category = 'ZERO_TRUST_MODE_CHANGED'
                 ORDER BY timestamp DESC
                 LIMIT ?
                """, (rs, row) -> new String[] {String.valueOf(instant(rs, 1)), rs.getString(2), rs.getString(3),
                rs.getString(4)}, limit);
    }

    /**
     * Console plan 5-2 ⑤: the measuring windows the AI monitor's reset closed, newest first. The table only holds the
     * windows kept before the reset was removed (console design 11.4).
     */
    List<PastWindow> pastWindows(int limit) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return List.of();
        }
        return operations.query("""
                SELECT started_at, ended_at, llm_decision_count, failure_rate, timeout_rate, p95_latency_ms,
                       recommendation, reset_by, reset_reason
                  FROM ctxa_ai_security_monitoring_session_summary
                 ORDER BY ended_at DESC
                 LIMIT ?
                """, (rs, row) -> new PastWindow(String.valueOf(instant(rs, 1)), String.valueOf(instant(rs, 2)),
                rs.getLong(3), rs.getObject(4, Double.class), rs.getObject(5, Double.class),
                rs.getObject(6, Double.class), rs.getString(7), rs.getString(8), rs.getString(9)), limit);
    }

    /** The first hour a mode decided in, for a mode no change on record started. */
    Instant firstDecisionIn(String mode) {
        JdbcOperations operations = jdbc.get();
        if (operations == null || mode == null) {
            return null;
        }
        Timestamp first = operations.queryForObject(
                "SELECT MIN(bucket_start) FROM ctxa_zt_stats_hourly WHERE decision_boundary_mode = ?", Timestamp.class,
                mode);
        return first == null ? null : first.toInstant();
    }

    private static String tenantClause(String tenant, List<Object> args) {
        if (tenant == null) {
            return "";
        }
        args.add(tenant);
        return " AND tenant_id = ?";
    }

    private static String modeClause(String mode, List<Object> args) {
        if (mode == null) {
            return "";
        }
        args.add(mode);
        return " AND decision_boundary_mode = ?";
    }

    private static Instant instant(ResultSet rs, int column) throws SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }
}
