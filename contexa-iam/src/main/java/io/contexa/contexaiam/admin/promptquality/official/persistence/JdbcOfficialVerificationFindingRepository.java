package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationFindingRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorFinding;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public final class JdbcOfficialVerificationFindingRepository implements OfficialVerificationFindingRepository {

    private final JdbcTemplate jdbcTemplate;
    private final OfficialVerificationSnapshotRowMapper rowMapper;

    public JdbcOfficialVerificationFindingRepository(
            JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
        this.rowMapper = Objects.requireNonNull(rowMapper, "rowMapper");
    }
    @Override
    public List<OperatorFinding> findByAggregateRunId(String aggregateRunId) {
        return jdbcTemplate.query("""
                        select finding_id, aggregate_run_id, official_run_id, package_id, certificate_id,
                               case_id, issue_id, metric_code, check_code, severity, operator_title,
                               operator_summary, problem_statement, root_cause, affected_target,
                               operator_reason, evidence_summary, evidence_path, expected_value,
                               actual_value, expected_result, actual_result, impact, remediation_owner,
                               next_action, reverify_criterion, customer_visible_severity,
                               related_process_step, comparison_field_key, comparison_state,
                               prompt_location, diagnostic_catalog_version, created_at
                          from official_verification_operator_finding
                         where aggregate_run_id = ?
                         order by metric_code asc, id asc
                        """,
                rowMapper::finding,
                aggregateRunId);
    }

    @Override
    public List<OperatorFinding> findByAggregateRunIds(List<String> aggregateRunIds) {
        if (aggregateRunIds == null || aggregateRunIds.isEmpty()) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select finding_id, aggregate_run_id, official_run_id, package_id, certificate_id,
                               case_id, issue_id, metric_code, check_code, severity, operator_title,
                               operator_summary, problem_statement, root_cause, affected_target,
                               operator_reason, evidence_summary, evidence_path, expected_value,
                               actual_value, expected_result, actual_result, impact, remediation_owner,
                               next_action, reverify_criterion, customer_visible_severity,
                               related_process_step, comparison_field_key, comparison_state,
                               prompt_location, diagnostic_catalog_version, created_at
                          from official_verification_operator_finding
                         where aggregate_run_id in (%s)
                         order by aggregate_run_id asc, metric_code asc, id asc
                        """.formatted(placeholders(aggregateRunIds)),
                rowMapper::finding,
                aggregateRunIds.toArray());
    }

    private String placeholders(List<String> values) {
        return values.stream().map(ignored -> "?").collect(Collectors.joining(", "));
    }
}