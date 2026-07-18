package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationReverificationWriter;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public final class JdbcOfficialVerificationReverificationWriter implements OfficialVerificationReverificationWriter {

    private static final String DELETE_SQL = """
            delete from official_verification_reverify_result result
            using sealed_evidence_package source_sealed, sealed_evidence_package fixed_sealed
             where result.source_package_id = ?
               and result.fixed_package_id = ?
               and coalesce(result.fixed_aggregate_run_id, '') = coalesce(?, '')
               and source_sealed.package_id = result.source_package_id
               and source_sealed.tenant_id = ?
               and fixed_sealed.package_id = result.fixed_package_id
               and fixed_sealed.tenant_id = ?
            """;
    private static final String INSERT_SQL = """
            insert into official_verification_reverify_result (
                result_id, source_package_id, source_aggregate_run_id,
                fixed_package_id, fixed_aggregate_run_id, source_finding_id,
                issue_id, metric_code, check_code, reverify_criterion,
                source_operator_reason, source_expected_value, source_actual_value,
                fixed_actual_value, resolved, resolution_state, operator_summary,
                created_by, diagnostic_catalog_version, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationReverificationWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void replace(String sourcePackageId, String fixedPackageId, String fixedAggregateRunId, String tenantId) {
        jdbcTemplate.update(
                DELETE_SQL, sourcePackageId, fixedPackageId, fixedAggregateRunId, tenantId, tenantId);
    }

    @Override
    public void insert(Command command) {
        jdbcTemplate.update(INSERT_SQL,
                "ovr-" + UUID.randomUUID(), command.sourcePackageId(), command.sourceAggregateRunId(),
                command.fixedPackageId(), command.fixedAggregateRunId(), command.findingId(), command.issueId(),
                command.metricCode(), command.checkCode(), command.reverifyCriterion(), command.sourceOperatorReason(),
                command.sourceExpectedValue(), command.sourceActualValue(), command.fixedActualValue(),
                command.resolved(), command.resolutionState(), command.operatorSummary(), command.createdBy(),
                command.diagnosticCatalogVersion(), Timestamp.from(Instant.now()));
    }
}
