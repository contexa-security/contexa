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
        Map<String, Object> row = aggregate(jdbcOperations, key, true);
        if (row == null || number(row.get("sample_count")).intValue() <= 0) {
            return null;
        }
        double confidence = bounded(number(row.get("avg_confidence")).doubleValue(), 0.0d, 1.0d);
        double risk = bounded(number(row.get("avg_risk")).doubleValue(), 0.0d, 1.0d);
        double normal = confidence <= 0.0d ? 0.75d : confidence;
        double mismatch = bounded(risk * (1.0d - normal), 0.0d, 1.0d);
        return entry(key, normal, risk, mismatch, row);
    }

    private HcadSemanticEvidenceEntry riskRequestSimilarity(
            JdbcOperations jdbcOperations,
            HcadSemanticEvidenceKey key) {
        Map<String, Object> row = aggregate(jdbcOperations, key, false);
        if (row == null || number(row.get("sample_count")).intValue() <= 0) {
            return null;
        }
        double risk = bounded(number(row.get("avg_risk")).doubleValue(), 0.0d, 1.0d);
        double confidence = bounded(number(row.get("avg_confidence")).doubleValue(), 0.0d, 1.0d);
        double similarityToRisk = risk <= 0.0d ? 0.75d : risk;
        double normal = bounded(1.0d - similarityToRisk, 0.0d, 1.0d);
        double mismatch = bounded(similarityToRisk * Math.max(confidence, 0.5d), 0.0d, 1.0d);
        return entry(key, normal, similarityToRisk, mismatch, row);
    }

    private Map<String, Object> aggregate(
            JdbcOperations jdbcOperations,
            HcadSemanticEvidenceKey key,
            boolean normal) {
        List<Map<String, Object>> rows = jdbcOperations.queryForList("""
                SELECT count(*) AS sample_count,
                       avg(coalesce(llm_risk_score, 0)) AS avg_risk,
                       avg(coalesce(llm_confidence, 0)) AS avg_confidence
                  FROM ai_security_decision_observation
                 WHERE coalesce(user_id, '') = coalesce(?, '')
                   AND (
                        coalesce(resource_id, '') = coalesce(?, '')
                        OR coalesce(request_path, '') LIKE ?
                   )
                   AND success = true
                   AND outcome_class <> 'UNKNOWN'
                   AND (
                        (? = true AND coalesce(final_action, '') IN ('ALLOW', 'PERMIT', 'NONE'))
                        OR (? = false AND coalesce(final_action, '') IN ('CHALLENGE', 'MFA', 'BLOCK', 'DENY'))
                   )
                """,
                value(key.userId()),
                value(key.resourceId()),
                "%" + value(key.resourceId()) + "%",
                normal,
                normal);
        return rows == null || rows.isEmpty() ? null : rows.get(0);
    }

    private HcadSemanticEvidenceEntry entry(
            HcadSemanticEvidenceKey key,
            double normal,
            double risk,
            double mismatch,
            Map<String, Object> row) {
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
                "{\"source\":\"ai_security_decision_observation\",\"sampleCount\":"
                        + number(row.get("sample_count")).intValue() + "}",
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

    private static String value(String value) {
        return value == null ? "" : value;
    }

    private static Number number(Object value) {
        return value instanceof Number number ? number : 0;
    }

    private static double bounded(double value, double min, double max) {
        return Math.max(min, Math.min(max, value));
    }

    private static String escapeJson(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
