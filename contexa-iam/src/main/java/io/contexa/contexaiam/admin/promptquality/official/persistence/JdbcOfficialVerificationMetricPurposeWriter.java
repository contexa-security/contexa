package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationMetricPurposeWriter;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;

public final class JdbcOfficialVerificationMetricPurposeWriter implements OfficialVerificationMetricPurposeWriter {

    private static final String INSERT_READINESS_SQL = """
            insert into official_metric_input_readiness_ledger (
                package_id, aggregate_run_id, metric_code, check_code,
                contract_version, readiness_state, detected_inputs_json,
                missing_inputs_json, readiness_scope, customer_visible, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;
    private static final String INSERT_PURPOSE_SQL = """
            insert into official_metric_purpose_evaluation_ledger (
                package_id, aggregate_run_id, metric_code, check_code,
                contract_version, purpose_statement, decision_utility,
                purpose_result, issue_key, customer_visible, readiness_scope,
                detected_signals_json, interpretation_links_json, expected_value,
                actual_value, remediation_owner, next_action, reverify_criterion,
                created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

    private static final String INSERT_CUSTOMER_DISPLAY_SQL = """
            insert into official_metric_customer_display_payload (
                package_id, aggregate_run_id, metric_code, check_code, contract_version,
                display_role, title, summary, evidence_text, why_it_matters,
                resolution_action, reverify_condition, context_items_json,
                bound_facts_json, raw_evidence_ref, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;
    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationMetricPurposeWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void insertReadiness(ReadinessCommand command) {
        jdbcTemplate.update(INSERT_READINESS_SQL,
                command.packageId(), command.aggregateRunId(), command.metricCode(), command.checkCode(),
                command.contractVersion(), command.readinessState(), command.detectedInputsJson(),
                command.missingInputsJson(), command.readinessScope(), command.customerVisible(), now());
    }

    @Override
    public void insertPurpose(PurposeCommand command) {
        jdbcTemplate.update(INSERT_PURPOSE_SQL,
                command.packageId(), command.aggregateRunId(), command.metricCode(), command.checkCode(),
                command.contractVersion(), command.purposeStatement(), command.decisionUtility(),
                command.purposeResult(), command.issueKey(), command.customerVisible(), command.readinessScope(),
                command.detectedSignalsJson(), command.interpretationLinksJson(), command.expectedValue(),
                command.actualValue(), command.remediationOwner(), command.nextAction(), command.reverifyCriterion(), now());
    }

    @Override
    public void insertCustomerDisplay(CustomerDisplayCommand command) {
        jdbcTemplate.update(INSERT_CUSTOMER_DISPLAY_SQL,
                command.packageId(), command.aggregateRunId(), command.metricCode(), command.checkCode(),
                command.contractVersion(), command.displayRole(), command.title(), command.summary(),
                command.evidenceText(), command.whyItMatters(), command.resolutionAction(),
                command.reverifyCondition(), command.contextItemsJson(), command.boundFactsJson(),
                command.rawEvidenceRef(), now());
    }
    private Timestamp now() {
        return Timestamp.from(Instant.now());
    }
}
