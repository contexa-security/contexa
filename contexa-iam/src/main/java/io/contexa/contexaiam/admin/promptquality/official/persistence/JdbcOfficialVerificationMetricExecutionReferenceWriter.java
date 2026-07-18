package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationMetricExecutionReferenceWriter;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;

public final class JdbcOfficialVerificationMetricExecutionReferenceWriter
        implements OfficialVerificationMetricExecutionReferenceWriter {

    private static final String UPDATE_SQL = """
            update official_verification_metric_execution_ledger execution
               set issue_ids_json = ?, problem_ids_json = ?, updated_at = ?
              from official_verification_run_batch batch
             where execution.aggregate_run_id = ?
               and upper(execution.metric_code) = ?
               and batch.aggregate_run_id = execution.aggregate_run_id
               and batch.package_id = ?
               and batch.tenant_id = ?
            """;

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationMetricExecutionReferenceWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void update(Command command) {
        jdbcTemplate.update(UPDATE_SQL,
                command.issueIdsJson(), command.problemIdsJson(), Timestamp.from(Instant.now()),
                command.aggregateRunId(), command.metricCode(), command.packageId(), command.tenantId());
    }
}
