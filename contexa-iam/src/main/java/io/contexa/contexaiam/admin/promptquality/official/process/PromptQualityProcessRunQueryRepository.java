package io.contexa.contexaiam.admin.promptquality.official.process;

import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

final class PromptQualityProcessRunQueryRepository {

    private final JdbcTemplate jdbcTemplate;

    PromptQualityProcessRunQueryRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }
    List<PromptQualityProcessStepSnapshot> steps(PromptQualityProcessScope scope) {
        if (scope == null) {
            return List.of();
        }
        return jdbcTemplate.query(
                """
                        select p.code as step_code,
                               s.sequence_no,
                               s.state,
                               s.domain_state_dimension,
                               s.domain_state_code,
                               s.evidence_ref,
                               s.route,
                               s.summary,
                               s.next_action,
                               s.started_at,
                               s.ended_at
                          from prompt_quality_process_run r
                          join prompt_quality_process_step_run s on s.run_id = r.id
                          join prompt_quality_process_definition p on p.id = s.step_process_id
                         where r.business_key = ?
                         order by s.sequence_no asc
                        """,
                this::mapStep,
                PromptQualityProcessRunStore.businessKey(scope));
    }

    List<PromptQualityProcessHistorySnapshot> history(PromptQualityProcessScope scope) {
        if (scope == null) {
            return List.of();
        }
        return jdbcTemplate.query(
                """
                        select h.process_code,
                               h.step_code,
                               h.from_state,
                               h.to_state,
                               h.from_domain_state_dimension,
                               h.from_domain_state_code,
                               h.to_domain_state_dimension,
                               h.to_domain_state_code,
                               h.evidence_ref,
                               h.changed_by,
                               h.reason,
                               h.changed_at
                          from prompt_quality_process_run r
                          join prompt_quality_process_state_history h on h.run_id = r.id
                         where r.business_key = ?
                         order by h.changed_at asc, h.id asc
                        """,
                this::mapHistory,
                PromptQualityProcessRunStore.businessKey(scope));
    }

    List<PromptQualityProcessEventSnapshot> events(PromptQualityProcessScope scope) {
        if (scope == null) {
            return List.of();
        }
        return jdbcTemplate.query(
                """
                        select p.code as step_code,
                               e.type,
                               e.payload_json,
                               e.occurred_at
                          from prompt_quality_process_run r
                          join prompt_quality_process_event e on e.run_id = r.id
                          left join prompt_quality_process_step_run s on s.id = e.step_run_id
                          left join prompt_quality_process_definition p on p.id = s.step_process_id
                         where r.business_key = ?
                         order by e.occurred_at asc, e.id asc
                        """,
                this::mapEvent,
                PromptQualityProcessRunStore.businessKey(scope));
    }

    private PromptQualityProcessStepSnapshot mapStep(ResultSet rs, int rowNum) throws SQLException {
        return new PromptQualityProcessStepSnapshot(
                rs.getString("step_code"),
                rs.getInt("sequence_no"),
                rs.getString("state"),
                rs.getString("domain_state_dimension"),
                rs.getString("domain_state_code"),
                rs.getString("evidence_ref"),
                rs.getString("route"),
                rs.getString("summary"),
                rs.getString("next_action"),
                instant(rs.getTimestamp("started_at")),
                instant(rs.getTimestamp("ended_at")));
    }

    private PromptQualityProcessHistorySnapshot mapHistory(ResultSet rs, int rowNum) throws SQLException {
        return new PromptQualityProcessHistorySnapshot(
                rs.getString("process_code"),
                rs.getString("step_code"),
                rs.getString("from_state"),
                rs.getString("to_state"),
                rs.getString("from_domain_state_dimension"),
                rs.getString("from_domain_state_code"),
                rs.getString("to_domain_state_dimension"),
                rs.getString("to_domain_state_code"),
                rs.getString("evidence_ref"),
                rs.getString("changed_by"),
                rs.getString("reason"),
                instant(rs.getTimestamp("changed_at")));
    }

    private PromptQualityProcessEventSnapshot mapEvent(ResultSet rs, int rowNum) throws SQLException {
        return new PromptQualityProcessEventSnapshot(
                rs.getString("step_code"),
                rs.getString("type"),
                rs.getString("payload_json"),
                instant(rs.getTimestamp("occurred_at")));
    }

    private Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

}
