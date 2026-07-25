package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorRunBatch;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotRepository;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public final class JdbcOfficialVerificationSnapshotRepository implements OfficialVerificationSnapshotRepository {

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationSnapshotRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }
    @Override
    public Optional<OperatorRunBatch> findCurrentBatch(
            String packageId,
            String aggregateRunId,
            String diagnosticCatalogVersion) {
        List<OperatorRunBatch> batches = aggregateRunId == null || aggregateRunId.isBlank()
                ? jdbcTemplate.query("""
                        select b.aggregate_run_id, b.package_id, b.certificate_id, b.case_id, b.scope_type,
                               b.expected_metric_count, b.actual_metric_count, b.passed_metric_count,
                               b.failed_metric_count, b.insufficient_metric_count, b.not_applicable_metric_count,
                               b.final_decision, b.blocked, b.block_reason_summary, b.prompt_hash, b.context_hash,
                               b.context_hash_state, b.template_resource_id, b.actual_resource_id,
                               b.resource_url_template, b.actual_request_path, b.http_method,
                               b.diagnostic_catalog_version, b.created_at
                          from official_verification_run_batch b
                          join sealed_evidence_package sealed on sealed.package_id = b.package_id
                           and sealed.tenant_id = b.tenant_id
                         where b.package_id = ?
                           and b.diagnostic_catalog_version = ?
                           and b.current_result = true
                         order by b.created_at desc
                         limit 1
                        """, this::mapBatch, packageId, diagnosticCatalogVersion)
                : jdbcTemplate.query("""
                        select b.aggregate_run_id, b.package_id, b.certificate_id, b.case_id, b.scope_type,
                               b.expected_metric_count, b.actual_metric_count, b.passed_metric_count,
                               b.failed_metric_count, b.insufficient_metric_count, b.not_applicable_metric_count,
                               b.final_decision, b.blocked, b.block_reason_summary, b.prompt_hash, b.context_hash,
                               b.context_hash_state, b.template_resource_id, b.actual_resource_id,
                               b.resource_url_template, b.actual_request_path, b.http_method,
                               b.diagnostic_catalog_version, b.created_at
                          from official_verification_run_batch b
                          join sealed_evidence_package sealed on sealed.package_id = b.package_id
                           and sealed.tenant_id = b.tenant_id
                         where b.package_id = ?
                           and b.aggregate_run_id = ?
                           and b.diagnostic_catalog_version = ?
                           and b.current_result = true
                         order by b.created_at desc
                         limit 1
                        """, this::mapBatch, packageId, aggregateRunId, diagnosticCatalogVersion);
        return batches.stream().findFirst();
    }

    @Override
    public List<OperatorRunBatch> findRecentCurrentBatches(String diagnosticCatalogVersion, int limit) {
        return jdbcTemplate.query("""
                        select b.aggregate_run_id, b.package_id, b.certificate_id, b.case_id, b.scope_type,
                               b.expected_metric_count, b.actual_metric_count, b.passed_metric_count,
                               b.failed_metric_count, b.insufficient_metric_count, b.not_applicable_metric_count,
                               b.final_decision, b.blocked, b.block_reason_summary, b.prompt_hash, b.context_hash,
                               b.context_hash_state, b.template_resource_id, b.actual_resource_id,
                               b.resource_url_template, b.actual_request_path, b.http_method,
                               b.diagnostic_catalog_version, b.created_at
                          from official_verification_run_batch b
                          join sealed_evidence_package sealed on sealed.package_id = b.package_id
                           and sealed.tenant_id = b.tenant_id
                         where b.diagnostic_catalog_version = ?
                           and b.current_result = true
                         order by b.created_at desc
                         limit ?
                        """,
                this::mapBatch,
                diagnosticCatalogVersion,
                limit);
    }

    private OperatorRunBatch mapBatch(ResultSet resultSet, int rowNumber) throws SQLException {
        return new OperatorRunBatch(
                resultSet.getString("aggregate_run_id"),
                resultSet.getString("package_id"),
                resultSet.getString("certificate_id"),
                resultSet.getString("case_id"),
                resultSet.getString("scope_type"),
                resultSet.getInt("expected_metric_count"),
                resultSet.getInt("actual_metric_count"),
                resultSet.getInt("passed_metric_count"),
                resultSet.getInt("failed_metric_count"),
                resultSet.getInt("insufficient_metric_count"),
                resultSet.getInt("not_applicable_metric_count"),
                resultSet.getString("final_decision"),
                resultSet.getBoolean("blocked"),
                resultSet.getString("block_reason_summary"),
                resultSet.getString("prompt_hash"),
                resultSet.getString("context_hash"),
                resultSet.getString("context_hash_state"),
                resultSet.getString("template_resource_id"),
                resultSet.getString("actual_resource_id"),
                resultSet.getString("resource_url_template"),
                resultSet.getString("actual_request_path"),
                resultSet.getString("http_method"),
                resultSet.getString("diagnostic_catalog_version"),
                instant(resultSet.getTimestamp("created_at")));
    }

    private Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}
