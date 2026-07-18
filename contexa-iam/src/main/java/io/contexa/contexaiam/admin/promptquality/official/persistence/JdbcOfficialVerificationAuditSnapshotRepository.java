package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationAuditSnapshotRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorAuditSnapshot;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public final class JdbcOfficialVerificationAuditSnapshotRepository implements OfficialVerificationAuditSnapshotRepository {

    private final JdbcTemplate jdbcTemplate;
    private final OfficialVerificationSnapshotRowMapper rowMapper;

    public JdbcOfficialVerificationAuditSnapshotRepository(
            JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
        this.rowMapper = Objects.requireNonNull(rowMapper, "rowMapper");
    }
    @Override
    public List<OperatorAuditSnapshot> findByAggregateRunId(String aggregateRunId) {
        List<OperatorAuditSnapshot> rows = jdbcTemplate.query("""
                        select snapshot_id, aggregate_run_id, package_id, certificate_id, case_id,
                               state, state_label, total_metric_count, failed_metric_count,
                               certificate_issued, prompt_hash, context_hash, blocking_findings_json,
                               next_actions_json, payload_json, created_by,
                               diagnostic_catalog_version, created_at
                          from official_verification_audit_snapshot
                         where aggregate_run_id = ?
                         order by created_at desc, id desc
                        """,
                rowMapper::auditSnapshot,
                aggregateRunId);
        return rows == null ? List.of() : rows;
    }

    @Override
    public List<OperatorAuditSnapshot> findByAggregateRunIds(List<String> aggregateRunIds) {
        if (aggregateRunIds == null || aggregateRunIds.isEmpty()) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select snapshot_id, aggregate_run_id, package_id, certificate_id, case_id,
                               state, state_label, total_metric_count, failed_metric_count,
                               certificate_issued, prompt_hash, context_hash, blocking_findings_json,
                               next_actions_json, payload_json, created_by,
                               diagnostic_catalog_version, created_at
                          from official_verification_audit_snapshot
                         where aggregate_run_id in (%s)
                         order by aggregate_run_id asc, created_at desc, id desc
                        """.formatted(placeholders(aggregateRunIds)),
                rowMapper::auditSnapshot,
                aggregateRunIds.toArray());
    }

    private String placeholders(List<String> values) {
        return values.stream().map(ignored -> "?").collect(Collectors.joining(", "));
    }
}