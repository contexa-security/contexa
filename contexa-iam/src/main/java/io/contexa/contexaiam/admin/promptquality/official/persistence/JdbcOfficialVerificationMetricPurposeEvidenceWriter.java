package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationMetricPurposeEvidenceWriter;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;

public final class JdbcOfficialVerificationMetricPurposeEvidenceWriter
        implements OfficialVerificationMetricPurposeEvidenceWriter {

    private static final String INSERT_SQL = """
            insert into official_metric_purpose_evidence_ledger (
                package_id, aggregate_run_id, purpose_evaluation_id,
                metric_code, check_code, contract_version, signal_key,
                prompt_location, evidence_value, evidence_hash, interpretation,
                purpose_result, customer_visible, readiness_scope,
                runtime_facts_json, context_items_json, created_at
            ) values (
                ?, ?,
                (
                    select e.id from official_metric_purpose_evaluation_ledger e
                     where e.aggregate_run_id = ?
                       and upper(e.metric_code) = ?
                       and e.check_code = ?
                     order by e.id desc limit 1
                ),
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """;

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationMetricPurposeEvidenceWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void insert(Command command) {
        jdbcTemplate.update(INSERT_SQL,
                command.packageId(), command.aggregateRunId(), command.aggregateRunId(), command.metricCode(),
                command.checkCode(), command.metricCode(), command.checkCode(), command.contractVersion(),
                command.signalKey(), command.promptLocation(), command.evidenceValue(), command.evidenceHash(),
                command.interpretation(), command.purposeResult(), command.customerVisible(), command.readinessScope(),
                command.runtimeFactsJson(), command.contextItemsJson(), Timestamp.from(Instant.now()));
    }
}
