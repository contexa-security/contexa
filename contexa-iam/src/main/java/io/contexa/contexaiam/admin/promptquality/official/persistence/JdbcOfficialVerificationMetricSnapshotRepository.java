package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationMetricSnapshotRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public final class JdbcOfficialVerificationMetricSnapshotRepository implements OfficialVerificationMetricSnapshotRepository {

    private final JdbcTemplate jdbcTemplate;
    private final OfficialVerificationSnapshotRowMapper rowMapper;

    public JdbcOfficialVerificationMetricSnapshotRepository(
            JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
        this.rowMapper = Objects.requireNonNull(rowMapper, "rowMapper");
    }
    @Override
    public List<OperatorMetricSnapshot> findByAggregateRunId(String aggregateRunId) {
        return jdbcTemplate.query("""
                        select aggregate_run_id, official_run_id, package_id, certificate_id, case_id,
                               metric_code, metric_name, metric_group, score, state, severity,
                               passed_checks, total_checks, failed_check_count, operator_title,
                               operator_summary, primary_failure_reason, remediation_owner,
                               next_action, reverify_criterion, diagnostic_catalog_version, created_at
                          from official_verification_metric_snapshot
                         where aggregate_run_id = ?
                         order by metric_code asc
                        """,
                rowMapper::metricSnapshot,
                aggregateRunId);
    }

    @Override
    public List<OperatorMetricSnapshot> findByAggregateRunIds(List<String> aggregateRunIds) {
        if (aggregateRunIds == null || aggregateRunIds.isEmpty()) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select aggregate_run_id, official_run_id, package_id, certificate_id, case_id,
                               metric_code, metric_name, metric_group, score, state, severity,
                               passed_checks, total_checks, failed_check_count, operator_title,
                               operator_summary, primary_failure_reason, remediation_owner,
                               next_action, reverify_criterion, diagnostic_catalog_version, created_at
                          from official_verification_metric_snapshot
                         where aggregate_run_id in (%s)
                         order by aggregate_run_id asc, metric_code asc
                        """.formatted(placeholders(aggregateRunIds)),
                rowMapper::metricSnapshot,
                aggregateRunIds.toArray());
    }

    private String placeholders(List<String> values) {
        return values.stream().map(ignored -> "?").collect(Collectors.joining(", "));
    }
}