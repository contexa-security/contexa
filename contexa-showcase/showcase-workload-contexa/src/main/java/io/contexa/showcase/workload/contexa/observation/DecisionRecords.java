package io.contexa.showcase.workload.contexa.observation;

import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

/**
 * Reads the engine's decision records ({@code ai_security_decision_observation}) by the orchestrator's decision id.
 * One request can have failed attempts and a final record; the newest is the final one (engine-spi 7). The time
 * columns are written by the engine without a time zone in the JVM zone, which is UTC in every showcase process
 * (ADR-09, ADR-25).
 */
public class DecisionRecords {

    /**
     * @param technicalFallback the engine fell back to CHALLENGE because the analysis failed; counted as unresolved,
     *                          never as a decision (deck p.24)
     */
    public record DecisionRecord(String observationId, String requestId, String userId, String finalAction,
                                 String proposedAction, Double riskScore, Double confidence, String modelId,
                                 boolean success, boolean technicalFallback, boolean parserFailure, String failureType,
                                 String fallbackCategory, String fallbackReason, Long llmLatencyMs, Long queueWaitMs,
                                 Long promptBuildMs, Long ragVectorMs, Long totalAnalysisMs, String contextBindingHash,
                                 String metadataJson, Instant decidedAt) {
    }

    private final JdbcTemplate engine;

    public DecisionRecords(JdbcTemplate engine) {
        this.engine = engine;
    }

    public List<DecisionRecord> byRequestId(String requestId) {
        return engine.query("""
                        select observation_id, request_id, user_id, final_action, proposed_action, llm_risk_score,
                               llm_confidence, model_id, success, technical_fallback, parser_failure, failure_type,
                               fallback_category, fallback_reason, llm_latency_ms, queue_wait_ms, prompt_build_ms,
                               rag_vector_ms, total_analysis_ms, context_binding_hash, metadata_json, decided_at
                          from ai_security_decision_observation
                         where request_id = ?
                         order by decided_at desc, observation_id desc""",
                (rs, n) -> read(rs), requestId);
    }

    private static DecisionRecord read(ResultSet rs) throws SQLException {
        Timestamp decided = rs.getTimestamp("decided_at");
        return new DecisionRecord(rs.getString("observation_id"), rs.getString("request_id"), rs.getString("user_id"),
                rs.getString("final_action"), rs.getString("proposed_action"), doubleOrNull(rs, "llm_risk_score"),
                doubleOrNull(rs, "llm_confidence"), rs.getString("model_id"), rs.getBoolean("success"),
                rs.getBoolean("technical_fallback"), rs.getBoolean("parser_failure"), rs.getString("failure_type"),
                rs.getString("fallback_category"), rs.getString("fallback_reason"), longOrNull(rs, "llm_latency_ms"),
                longOrNull(rs, "queue_wait_ms"), longOrNull(rs, "prompt_build_ms"), longOrNull(rs, "rag_vector_ms"),
                longOrNull(rs, "total_analysis_ms"), rs.getString("context_binding_hash"), rs.getString("metadata_json"),
                decided == null ? null : decided.toLocalDateTime().toInstant(ZoneOffset.UTC));
    }

    private static Double doubleOrNull(ResultSet rs, String column) throws SQLException {
        double value = rs.getDouble(column);
        return rs.wasNull() ? null : value;
    }

    private static Long longOrNull(ResultSet rs, String column) throws SQLException {
        long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }
}
