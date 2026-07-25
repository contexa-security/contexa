package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotCleanupRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationResolutionCleanup;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcOfficialVerificationSnapshotCleanupRepository
        implements OfficialVerificationSnapshotCleanupRepository {

    private final JdbcTemplate jdbcTemplate;
    private final OfficialVerificationResolutionCleanup resolutionCleanup;

    public JdbcOfficialVerificationSnapshotCleanupRepository(JdbcTemplate jdbcTemplate) {
        this(jdbcTemplate, OfficialVerificationResolutionCleanup.none());
    }

    public JdbcOfficialVerificationSnapshotCleanupRepository(
            JdbcTemplate jdbcTemplate,
            OfficialVerificationResolutionCleanup resolutionCleanup) {
        this.jdbcTemplate = jdbcTemplate;
        this.resolutionCleanup = resolutionCleanup;
    }
    @Override
    public void deleteDiagnosticPackage(String tenantId, String packageId) {
        String tenant = required(tenantId, "tenantId");
        String evidencePackage = required(packageId, "packageId");

        resolutionCleanup.deleteDiagnosticPackage(tenant, evidencePackage);

        jdbcTemplate.update("""
                        delete from official_verification_metric_execution_ledger execution
                        using sealed_evidence_package sealed
                         where execution.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_verification_execution_state_history history
                        using sealed_evidence_package sealed
                         where history.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_verification_reverify_result result
                        using sealed_evidence_package sealed
                         where (
                               result.source_package_id = sealed.package_id
                               or result.fixed_package_id = sealed.package_id
                           )
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_verification_audit_snapshot audit
                        using sealed_evidence_package sealed
                         where audit.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_verification_operator_remediation_group remediation
                        using sealed_evidence_package sealed
                         where remediation.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_metric_customer_display_payload display
                        using sealed_evidence_package sealed
                         where display.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_metric_purpose_evidence_ledger purpose
                        using sealed_evidence_package sealed
                         where purpose.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_metric_purpose_evaluation_ledger purpose
                        using sealed_evidence_package sealed
                         where purpose.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_metric_input_readiness_ledger input
                        using sealed_evidence_package sealed
                         where input.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_prompt_signal_ledger signal
                        using sealed_evidence_package sealed
                         where signal.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_actual_prompt_problem_ledger problem
                        using sealed_evidence_package sealed
                         where problem.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_verification_prompt_comparison comparison
                        using sealed_evidence_package sealed
                         where comparison.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_prompt_field_diff_ledger field_diff
                        using sealed_evidence_package sealed
                         where field_diff.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_prompt_field_value_ledger field_value
                        using sealed_evidence_package sealed
                         where field_value.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_prompt_generation_lineage lineage
                        using sealed_evidence_package sealed
                         where lineage.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_prompt_projection_ledger projection
                        using sealed_evidence_package sealed
                         where projection.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_prompt_field_state_ledger field_state
                        using sealed_evidence_package sealed
                         where field_state.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_verification_operator_finding finding
                        using sealed_evidence_package sealed
                         where finding.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_verification_metric_snapshot metric
                        using sealed_evidence_package sealed
                         where metric.package_id = sealed.package_id
                           and sealed.package_id = ?
                           and sealed.tenant_id = ?
                        """, evidencePackage, tenant);
        jdbcTemplate.update("""
                        delete from official_verification_run_batch
                         where package_id = ?
                           and tenant_id = ?
                        """, evidencePackage, tenant);
    }

    @Override
    public void deleteAggregateSnapshot(String tenantId, String packageId, String aggregateRunId) {
        String tenant = required(tenantId, "tenantId");
        String evidencePackage = required(packageId, "packageId");
        String aggregate = required(aggregateRunId, "aggregateRunId");

        deleteAggregateRows("""
                delete from official_verification_operator_remediation_group remediation
                using official_verification_run_batch batch
                 where remediation.aggregate_run_id = batch.aggregate_run_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        deleteAggregateRows("""
                delete from official_metric_customer_display_payload display
                using official_verification_run_batch batch
                 where display.aggregate_run_id = batch.aggregate_run_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        deleteAggregateRows("""
                delete from official_metric_purpose_evidence_ledger purpose
                using official_verification_run_batch batch
                 where purpose.aggregate_run_id = batch.aggregate_run_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        deleteAggregateRows("""
                delete from official_metric_purpose_evaluation_ledger purpose
                using official_verification_run_batch batch
                 where purpose.aggregate_run_id = batch.aggregate_run_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        deleteAggregateRows("""
                delete from official_metric_input_readiness_ledger input
                using official_verification_run_batch batch
                 where input.aggregate_run_id = batch.aggregate_run_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        deleteAggregateRows("""
                delete from official_prompt_signal_ledger signal
                using official_verification_run_batch batch
                 where signal.aggregate_run_id = batch.aggregate_run_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        deleteAggregateRows("""
                delete from official_actual_prompt_problem_ledger problem
                using official_verification_run_batch batch
                 where problem.aggregate_run_id = batch.aggregate_run_id
                   and problem.package_id = batch.package_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        deleteAggregateRows("""
                delete from official_verification_prompt_comparison comparison
                using official_verification_run_batch batch
                 where comparison.aggregate_run_id = batch.aggregate_run_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        deleteAggregateRows("""
                delete from official_prompt_field_diff_ledger field_diff
                using official_verification_run_batch batch
                 where field_diff.aggregate_run_id = batch.aggregate_run_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        deleteAggregateRows("""
                delete from official_prompt_field_value_ledger field_value
                using official_verification_run_batch batch
                 where field_value.aggregate_run_id = batch.aggregate_run_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        deleteAggregateRows("""
                delete from official_prompt_generation_lineage lineage
                using official_verification_run_batch batch
                 where lineage.aggregate_run_id = batch.aggregate_run_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        deleteAggregateRows("""
                delete from official_prompt_projection_ledger projection
                using official_verification_run_batch batch
                 where projection.aggregate_run_id = batch.aggregate_run_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        deleteAggregateRows("""
                delete from official_prompt_field_state_ledger field_state
                using official_verification_run_batch batch
                 where field_state.aggregate_run_id = batch.aggregate_run_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        deleteAggregateRows("""
                delete from official_verification_operator_finding finding
                using official_verification_run_batch batch
                 where finding.aggregate_run_id = batch.aggregate_run_id
                   and finding.package_id = batch.package_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        deleteAggregateRows("""
                delete from official_verification_metric_snapshot metric
                using official_verification_run_batch batch
                 where metric.aggregate_run_id = batch.aggregate_run_id
                   and metric.package_id = batch.package_id
                   and batch.aggregate_run_id = ?
                   and batch.package_id = ?
                   and batch.tenant_id = ?
                """, aggregate, evidencePackage, tenant);
        jdbcTemplate.update("""
                delete from official_verification_run_batch
                 where aggregate_run_id = ?
                   and package_id = ?
                   and tenant_id = ?
                """, aggregate, evidencePackage, tenant);
    }

    private void deleteAggregateRows(
            String sql,
            String aggregateRunId,
            String packageId,
            String tenantId) {
        jdbcTemplate.update(sql, aggregateRunId, packageId, tenantId);
    }

    private String required(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " is required for official verification snapshot persistence.");
        }
        return value.trim();
    }

}
