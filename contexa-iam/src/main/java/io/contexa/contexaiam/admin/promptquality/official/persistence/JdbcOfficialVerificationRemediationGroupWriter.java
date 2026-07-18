package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationRemediationGroupWriter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public final class JdbcOfficialVerificationRemediationGroupWriter
        implements OfficialVerificationRemediationGroupWriter {

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationRemediationGroupWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void insert(RemediationGroupCommand command) {
        Objects.requireNonNull(command, "command");
        GroupIdentity identity = Objects.requireNonNull(command.identity(), "identity");
        GroupClassification classification = Objects.requireNonNull(command.classification(), "classification");
        GroupNarrative narrative = Objects.requireNonNull(command.narrative(), "narrative");
        jdbcTemplate.update("""
                        insert into official_verification_operator_remediation_group (
                            group_id, aggregate_run_id, package_id, certificate_id, case_id,
                            root_cause_key, remediation_owner, operator_title, operator_reason,
                            next_action, reverify_criterion, affected_metric_codes,
                            affected_check_codes, finding_count, related_process_step,
                            comparison_field_keys, prompt_locations,
                            diagnostic_catalog_version, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                fit("org-" + UUID.randomUUID(), 256),
                fit(identity.aggregateRunId(), 256),
                fit(identity.packageId(), 256),
                fit(identity.certificateId(), 256),
                fit(identity.caseId(), 256),
                fit(classification.rootCauseKey(), 256),
                fit(narrative.remediationOwner(), 128),
                fit(narrative.title(), 255),
                narrative.reason(),
                narrative.nextAction(),
                narrative.reverifyCriterion(),
                fit(classification.affectedMetricCodes(), 512),
                fit(classification.affectedCheckCodes(), 2048),
                classification.findingCount(),
                fit(classification.relatedProcessStep(), 128),
                fit(classification.comparisonFieldKeys(), 2048),
                fit(classification.promptLocations(), 2048),
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
