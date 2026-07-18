package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationFindingWriter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public final class JdbcOfficialVerificationFindingWriter implements OfficialVerificationFindingWriter {

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationFindingWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void insert(FindingCommand command) {
        Objects.requireNonNull(command, "command");
        FindingIdentity identity = Objects.requireNonNull(command.identity(), "identity");
        FindingClassification classification = Objects.requireNonNull(command.classification(), "classification");
        FindingNarrative narrative = Objects.requireNonNull(command.narrative(), "narrative");
        jdbcTemplate.update("""
                        insert into official_verification_operator_finding (
                            finding_id, aggregate_run_id, official_run_id, package_id,
                            certificate_id, case_id, issue_id, metric_code,
                            check_code, severity, operator_title, operator_summary,
                            problem_statement, root_cause, affected_target, operator_reason,
                            evidence_summary, evidence_path, expected_value, actual_value,
                            expected_result, actual_result, impact, remediation_owner,
                            next_action, reverify_criterion, customer_visible_severity,
                            related_process_step, comparison_field_key, comparison_state,
                            prompt_location, diagnostic_catalog_version, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                fit("of-" + UUID.randomUUID(), 256),
                fit(identity.aggregateRunId(), 256),
                fit(identity.officialRunId(), 256),
                fit(identity.packageId(), 256),
                fit(identity.certificateId(), 256),
                fit(identity.caseId(), 256),
                fit(identity.issueId(), 256),
                fit(identity.metricCode(), 32),
                fit(identity.checkCode(), 128),
                fit(classification.severity(), 32),
                fit(narrative.title(), 255),
                narrative.summary(),
                narrative.problemStatement(),
                narrative.rootCause(),
                fit(narrative.affectedTarget(), 256),
                narrative.operatorReason(),
                narrative.evidenceSummary(),
                fit(classification.evidencePath(), 512),
                classification.expectedValue(),
                classification.actualValue(),
                narrative.expectedResult(),
                narrative.actualResult(),
                narrative.impact(),
                fit(narrative.remediationOwner(), 128),
                narrative.nextAction(),
                narrative.reverifyCriterion(),
                fit(narrative.customerVisibleSeverity(), 64),
                fit(classification.relatedProcessStep(), 128),
                fit(classification.comparisonFieldKey(), 512),
                fit(classification.comparisonState(), 64),
                fit(classification.promptLocation(), 256),
                OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                Timestamp.from(Instant.now()));
    }

    private String fit(String value, int maxLength) {
        if (!StringUtils.hasText(value) || maxLength <= 0) {
            return value;
        }
        String trimmed = value.trim();
        return trimmed.length() <= maxLength ? trimmed : trimmed.substring(0, maxLength);
    }
}
