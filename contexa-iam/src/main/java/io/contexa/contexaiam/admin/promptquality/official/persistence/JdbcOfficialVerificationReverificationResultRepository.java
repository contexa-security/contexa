package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorReverificationResult;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationReverificationResultRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Objects;

public final class JdbcOfficialVerificationReverificationResultRepository
        implements OfficialVerificationReverificationResultRepository {

    private static final String SELECT = """
            select result_id, source_package_id, source_aggregate_run_id,
                   fixed_package_id, fixed_aggregate_run_id, source_finding_id,
                   issue_id, metric_code, check_code, reverify_criterion,
                   source_operator_reason, source_expected_value, source_actual_value,
                   fixed_actual_value, resolved, resolution_state, operator_summary,
                   created_by, diagnostic_catalog_version, created_at
              from official_verification_reverify_result
            """;

    private final JdbcTemplate jdbcTemplate;
    private final OfficialVerificationSnapshotRowMapper rowMapper;

    public JdbcOfficialVerificationReverificationResultRepository(
            JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
        this.rowMapper = Objects.requireNonNull(rowMapper, "rowMapper");
    }

    @Override
    public List<OperatorReverificationResult> findBySource(
            String sourcePackageId,
            String sourceAggregateRunId) {
        if (StringUtils.hasText(sourceAggregateRunId)) {
            return jdbcTemplate.query(SELECT + """
                     where source_package_id = ?
                       and source_aggregate_run_id = ?
                     order by created_at desc
                     limit 50
                    """, rowMapper::reverificationResult, sourcePackageId, sourceAggregateRunId);
        }
        return jdbcTemplate.query(SELECT + """
                 where source_package_id = ?
                 order by created_at desc
                 limit 50
                """, rowMapper::reverificationResult, sourcePackageId);
    }
}
