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
package io.contexa.contexacore.hcad.semantic;

import io.contexa.contexacore.properties.HcadProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcOperations;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import java.util.function.Supplier;

@Slf4j
public class JdbcHcadSemanticEvidenceWarmupService implements HcadSemanticEvidenceWarmupService {

    private static final Executor DEFAULT_EXECUTOR = ForkJoinPool.commonPool();

    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final HcadProperties hcadProperties;
    private final Executor executor;

    public JdbcHcadSemanticEvidenceWarmupService(
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            HcadProperties hcadProperties,
            Executor executor) {
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.hcadProperties = hcadProperties;
        this.executor = executor == null ? DEFAULT_EXECUTOR : executor;
    }

    @Override
    public HcadSemanticEvidenceWarmupResult requestWarmup(
            HcadSemanticEvidenceWarmupRequest request,
            HcadSemanticEvidenceCache cache) {
        if (request == null || request.key() == null || cache == null || hcadProperties == null) {
            return HcadSemanticEvidenceWarmupResult.unavailable("WARMUP_UNAVAILABLE");
        }
        JdbcOperations jdbcOperations = jdbcOperationsSupplier.get();
        if (jdbcOperations == null) {
            return HcadSemanticEvidenceWarmupResult.unavailable("JDBC_UNAVAILABLE");
        }
        executor.execute(() -> materialize(jdbcOperations, request, cache));
        return HcadSemanticEvidenceWarmupResult.queued();
    }

    private void materialize(
            JdbcOperations jdbcOperations,
            HcadSemanticEvidenceWarmupRequest request,
            HcadSemanticEvidenceCache cache) {
        HcadSemanticEvidenceKey key = request.key();
        try {
            HcadSemanticEvidenceEntry entry = switch (key.type()) {
                case NORMAL_REQUEST_SIMILARITY -> normalRequestSimilarity(jdbcOperations, key);
                case RISK_REQUEST_SIMILARITY -> riskRequestSimilarity(jdbcOperations, key);
                case RESOURCE_LLM_DECISION_SUMMARY -> resourceDecisionSummary(jdbcOperations, key);
                default -> null;
            };
            if (entry == null) {
                cache.putSourceAbsent(key, Duration.ofSeconds(negativeTtlSeconds()));
                return;
            }
            cache.put(entry, Duration.ofSeconds(ttlSeconds(key)));
        } catch (DataAccessException ex) {
            log.debug("[HCAD] semantic evidence warm-up failed: type={}, resourceId={}",
                    key.type(), key.resourceId(), ex);
            cache.put(
                    failedEntry(key, ex),
                    Duration.ofSeconds(Math.max(1L, hcadProperties.getSemanticEvidence().getWarmupRetryTtlSeconds())));
        }
    }

    private HcadSemanticEvidenceEntry normalRequestSimilarity(
            JdbcOperations jdbcOperations,
            HcadSemanticEvidenceKey key) {
        Map<String, Object> row = aggregateNormal(jdbcOperations, key);
        if (empty(row)) {
            return null;
        }
        double confidence = bounded(number(row.get("avg_confidence")).doubleValue(), 0.0d, 1.0d);
        double risk = bounded(number(row.get("avg_risk")).doubleValue(), 0.0d, 1.0d);
        double normal = confidence <= 0.0d ? 0.75d : confidence;
        double mismatch = bounded(risk * (1.0d - normal), 0.0d, 1.0d);
        return entry(key, normal, risk, mismatch, row, "normal", "ALLOW");
    }

    private HcadSemanticEvidenceEntry riskRequestSimilarity(
            JdbcOperations jdbcOperations,
            HcadSemanticEvidenceKey key) {
        Map<String, Object> row = aggregateRisk(jdbcOperations, key);
        if (empty(row)) {
            return null;
        }
        double confidence = bounded(number(row.get("avg_confidence")).doubleValue(), 0.0d, 1.0d);
        double risk = bounded(number(row.get("avg_risk")).doubleValue(), 0.0d, 1.0d);
        double riskSimilarity = bounded(Math.max(risk, confidence * 0.9d), 0.0d, 1.0d);
        return entry(key, null, riskSimilarity, riskSimilarity, row, "risk", "CHALLENGE_BLOCK");
    }

    private HcadSemanticEvidenceEntry resourceDecisionSummary(
            JdbcOperations jdbcOperations,
            HcadSemanticEvidenceKey key) {
        Map<String, Object> row = aggregateResourceSummary(jdbcOperations, key);
        if (empty(row)) {
            return null;
        }
        double riskCount = number(row.get("challenge_count")).doubleValue()
                + number(row.get("block_count")).doubleValue();
        double total = Math.max(1.0d, number(row.get("sample_count")).doubleValue());
        double riskRatio = bounded(riskCount / total, 0.0d, 1.0d);
        double avgRisk = bounded(number(row.get("avg_risk")).doubleValue(), 0.0d, 1.0d);
        double riskSimilarity = bounded(Math.max(riskRatio, avgRisk), 0.0d, 1.0d);
        return entry(key, null, riskSimilarity, riskSimilarity, row, "resourceDecisionSummary", "ALLOW_CHALLENGE_BLOCK");
    }

    private Map<String, Object> aggregateNormal(
            JdbcOperations jdbcOperations,
            HcadSemanticEvidenceKey key) {
        return firstRow(jdbcOperations.queryForList("""
                SELECT count(*) AS sample_count,
                       avg(coalesce(llm_risk_score, 0)) AS avg_risk,
                       avg(coalesce(llm_confidence, 0)) AS avg_confidence,
                       max(decided_at) AS last_decision_at
                  FROM ai_security_decision_observation
                 WHERE coalesce(user_id, '') = coalesce(?, '')
                   AND (
                        coalesce(resource_id, '') = coalesce(?, '')
                        OR coalesce(request_path, '') LIKE ?
                   )
                   AND success = true
                   AND outcome_class <> 'UNKNOWN'
                   AND upper(coalesce(nullif(final_action, 'PENDING_ANALYSIS'), nullif(proposed_action, ''), '')) = 'ALLOW'
                """,
                value(key.userId()),
                value(key.resourceId()),
                resourceLikePattern(key.resourceId())));
    }

    private Map<String, Object> aggregateRisk(
            JdbcOperations jdbcOperations,
            HcadSemanticEvidenceKey key) {
        return firstRow(jdbcOperations.queryForList("""
                SELECT count(*) AS sample_count,
                       avg(coalesce(llm_risk_score, 0)) AS avg_risk,
                       avg(coalesce(llm_confidence, 0)) AS avg_confidence,
                       max(decided_at) AS last_decision_at,
                       sum(CASE WHEN upper(coalesce(nullif(final_action, 'PENDING_ANALYSIS'), nullif(proposed_action, ''), '')) = 'CHALLENGE' THEN 1 ELSE 0 END) AS challenge_count,
                       sum(CASE WHEN upper(coalesce(nullif(final_action, 'PENDING_ANALYSIS'), nullif(proposed_action, ''), '')) = 'BLOCK' THEN 1 ELSE 0 END) AS block_count
                  FROM ai_security_decision_observation
                 WHERE coalesce(user_id, '') = coalesce(?, '')
                   AND (
                        coalesce(resource_id, '') = coalesce(?, '')
                        OR coalesce(request_path, '') LIKE ?
                   )
                   AND success = true
                   AND outcome_class <> 'UNKNOWN'
                   AND upper(coalesce(nullif(final_action, 'PENDING_ANALYSIS'), nullif(proposed_action, ''), '')) IN ('CHALLENGE', 'BLOCK')
                """,
                value(key.userId()),
                value(key.resourceId()),
                resourceLikePattern(key.resourceId())));
    }

    private Map<String, Object> aggregateResourceSummary(
            JdbcOperations jdbcOperations,
            HcadSemanticEvidenceKey key) {
        return firstRow(jdbcOperations.queryForList("""
                SELECT count(*) AS sample_count,
                       avg(coalesce(llm_risk_score, 0)) AS avg_risk,
                       avg(coalesce(llm_confidence, 0)) AS avg_confidence,
                       max(decided_at) AS last_decision_at,
                       sum(CASE WHEN upper(coalesce(nullif(final_action, 'PENDING_ANALYSIS'), nullif(proposed_action, ''), '')) = 'ALLOW' THEN 1 ELSE 0 END) AS allow_count,
                       sum(CASE WHEN upper(coalesce(nullif(final_action, 'PENDING_ANALYSIS'), nullif(proposed_action, ''), '')) = 'CHALLENGE' THEN 1 ELSE 0 END) AS challenge_count,
                       sum(CASE WHEN upper(coalesce(nullif(final_action, 'PENDING_ANALYSIS'), nullif(proposed_action, ''), '')) = 'BLOCK' THEN 1 ELSE 0 END) AS block_count
                  FROM ai_security_decision_observation
                 WHERE (
                        coalesce(resource_id, '') = coalesce(?, '')
                        OR coalesce(request_path, '') LIKE ?
                   )
                   AND success = true
                   AND outcome_class <> 'UNKNOWN'
                   AND upper(coalesce(nullif(final_action, 'PENDING_ANALYSIS'), nullif(proposed_action, ''), '')) IN ('ALLOW', 'CHALLENGE', 'BLOCK')
                """,
                value(key.resourceId()),
                resourceLikePattern(key.resourceId())));
    }

    private HcadSemanticEvidenceEntry entry(
            HcadSemanticEvidenceKey key,
            Double normal,
            Double risk,
            Double mismatch,
            Map<String, Object> row,
            String evidenceKind,
            String actionFamily) {
        Instant now = Instant.now();
        return new HcadSemanticEvidenceEntry(
                key,
                HcadSemanticEvidenceCacheStatus.HIT,
                "ai_security_decision_observation",
                key.evidenceVersion(),
                key.embeddingModel(),
                key.dimension(),
                normal,
                risk,
                mismatch,
                summaryJson(row, evidenceKind, actionFamily),
                List.of("CACHE_MISS_SOURCE_AVAILABLE", "WARMUP_COMPLETED"),
                now,
                now.plusSeconds(ttlSeconds(key)));
    }

    private HcadSemanticEvidenceEntry failedEntry(HcadSemanticEvidenceKey key, DataAccessException exception) {
        Instant now = Instant.now();
        return new HcadSemanticEvidenceEntry(
                key,
                HcadSemanticEvidenceCacheStatus.WARMUP_FAILED,
                "ai_security_decision_observation",
                key.evidenceVersion(),
                key.embeddingModel(),
                key.dimension(),
                null,
                null,
                null,
                "{\"source\":\"ai_security_decision_observation\",\"failure\":\""
                        + escapeJson(exception.getClass().getSimpleName()) + "\"}",
                List.of("WARMUP_FAILED"),
                now,
                now.plusSeconds(Math.max(1L, hcadProperties.getSemanticEvidence().getWarmupRetryTtlSeconds())));
    }

    private long ttlSeconds(HcadSemanticEvidenceKey key) {
        long seconds = hcadProperties.getSemanticEvidence().ttlSecondsFor(key.type());
        return Math.max(1L, seconds);
    }

    private long negativeTtlSeconds() {
        return Math.max(1L, hcadProperties.getSemanticEvidence().getSourceAbsentNegativeTtlSeconds());
    }

    private static Map<String, Object> firstRow(List<Map<String, Object>> rows) {
        return rows == null || rows.isEmpty() ? null : rows.get(0);
    }

    private static boolean empty(Map<String, Object> row) {
        return row == null || number(row.get("sample_count")).intValue() <= 0;
    }

    private static String value(String value) {
        return value == null ? "" : value;
    }

    private static String resourceLikePattern(String resourceId) {
        String value = value(resourceId);
        int placeholder = value.indexOf('{');
        if (placeholder > 0) {
            return value.substring(0, placeholder) + "%";
        }
        return "%" + value + "%";
    }

    private static Number number(Object value) {
        return value instanceof Number number ? number : 0;
    }

    private static double bounded(double value, double min, double max) {
        return Math.max(min, Math.min(max, value));
    }

    private static String summaryJson(Map<String, Object> row, String evidenceKind, String actionFamily) {
        StringBuilder builder = new StringBuilder();
        builder.append('{');
        field(builder, "source", "ai_security_decision_observation");
        field(builder, "evidenceKind", evidenceKind);
        field(builder, "actionFamily", actionFamily);
        numberField(builder, "sampleCount", number(row.get("sample_count")));
        numberField(builder, "avgRisk", number(row.get("avg_risk")));
        numberField(builder, "avgConfidence", number(row.get("avg_confidence")));
        numberField(builder, "allowCount", number(row.get("allow_count")));
        numberField(builder, "challengeCount", number(row.get("challenge_count")));
        numberField(builder, "blockCount", number(row.get("block_count")));
        field(builder, "lastDecisionAt", text(row.get("last_decision_at")));
        builder.append('}');
        return builder.toString();
    }

    private static void field(StringBuilder builder, String name, String value) {
        appendSeparator(builder);
        builder.append('"').append(escapeJson(name)).append("\":");
        if (value == null) {
            builder.append("null");
        } else {
            builder.append('"').append(escapeJson(value)).append('"');
        }
    }

    private static void numberField(StringBuilder builder, String name, Number value) {
        appendSeparator(builder);
        builder.append('"').append(escapeJson(name)).append("\":");
        builder.append(value == null ? 0 : value);
    }

    private static void appendSeparator(StringBuilder builder) {
        if (builder.length() > 1 && builder.charAt(builder.length() - 1) != '{') {
            builder.append(',');
        }
    }

    private static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }

    private static String escapeJson(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}

