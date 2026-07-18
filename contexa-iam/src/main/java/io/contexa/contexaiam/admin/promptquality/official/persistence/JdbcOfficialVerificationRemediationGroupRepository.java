package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationRemediationGroupRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorRemediationGroup;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public final class JdbcOfficialVerificationRemediationGroupRepository implements OfficialVerificationRemediationGroupRepository {

    private final JdbcTemplate jdbcTemplate;
    private final OfficialVerificationSnapshotRowMapper rowMapper;

    public JdbcOfficialVerificationRemediationGroupRepository(
            JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
        this.rowMapper = Objects.requireNonNull(rowMapper, "rowMapper");
    }
    @Override
    public List<OperatorRemediationGroup> findByAggregateRunId(String aggregateRunId) {
        return jdbcTemplate.query("""
                        select group_id, aggregate_run_id, package_id, certificate_id, case_id,
                               root_cause_key, remediation_owner, operator_title, operator_reason,
                               next_action, reverify_criterion, affected_metric_codes,
                               affected_check_codes, finding_count, related_process_step,
                               comparison_field_keys, prompt_locations, diagnostic_catalog_version, created_at
                          from official_verification_operator_remediation_group
                         where aggregate_run_id = ?
                         order by finding_count desc, remediation_owner asc, id asc
                        """,
                rowMapper::remediationGroup,
                aggregateRunId);
    }

    @Override
    public List<OperatorRemediationGroup> findByAggregateRunIds(List<String> aggregateRunIds) {
        if (aggregateRunIds == null || aggregateRunIds.isEmpty()) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select group_id, aggregate_run_id, package_id, certificate_id, case_id,
                               root_cause_key, remediation_owner, operator_title, operator_reason,
                               next_action, reverify_criterion, affected_metric_codes,
                               affected_check_codes, finding_count, related_process_step,
                               comparison_field_keys, prompt_locations, diagnostic_catalog_version, created_at
                          from official_verification_operator_remediation_group
                         where aggregate_run_id in (%s)
                         order by aggregate_run_id asc, finding_count desc, remediation_owner asc, id asc
                        """.formatted(placeholders(aggregateRunIds)),
                rowMapper::remediationGroup,
                aggregateRunIds.toArray());
    }

    private String placeholders(List<String> values) {
        return values.stream().map(ignored -> "?").collect(Collectors.joining(", "));
    }
}