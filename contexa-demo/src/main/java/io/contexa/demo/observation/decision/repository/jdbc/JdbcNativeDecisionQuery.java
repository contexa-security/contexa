package io.contexa.demo.observation.decision.repository.jdbc;

import io.contexa.demo.observation.decision.dto.NativeDecisionView;
import io.contexa.demo.observation.decision.repository.NativeDecisionQuery;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
@Profile("contexa")
public class JdbcNativeDecisionQuery extends AbstractJdbcRepository implements NativeDecisionQuery {

    public JdbcNativeDecisionQuery(@Qualifier("contexaJdbcTemplate") JdbcOperations jdbc) {
        super(jdbc);
    }

    @Override
    public List<NativeDecisionView> find(UUID requestId) {
        return jdbc.query("""
                select observation_id, event_id, request_id, processing_generation, final_action, proposed_action,
                       decision_boundary_mode, success, llm_decision_present, technical_fallback, failure_type, decided_at
                from ai_security_decision_observation where request_id = ? order by created_at, observation_id limit 100
                """, (rs, row) -> new NativeDecisionView(rs.getString("observation_id"), rs.getString("event_id"),
                rs.getString("request_id"), rs.getString("processing_generation"), rs.getString("final_action"),
                rs.getString("proposed_action"), rs.getString("decision_boundary_mode"),
                rs.getObject("success", Boolean.class), rs.getObject("llm_decision_present", Boolean.class),
                rs.getObject("technical_fallback", Boolean.class), rs.getString("failure_type"),
                rs.getTimestamp("decided_at") == null ? null : rs.getTimestamp("decided_at").toLocalDateTime()),
                requestId.toString());
    }
}
