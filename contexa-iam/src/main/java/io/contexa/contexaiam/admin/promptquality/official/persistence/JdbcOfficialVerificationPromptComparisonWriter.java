package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPromptComparisonWriter;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public final class JdbcOfficialVerificationPromptComparisonWriter
        implements OfficialVerificationPromptComparisonWriter {

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationPromptComparisonWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void insert(PromptComparisonCommand command) {
        Objects.requireNonNull(command, "command");
        OfficialVerificationPromptComparison comparison = Objects.requireNonNull(
                command.comparison(), "comparison");
        jdbcTemplate.update("""
                        insert into official_verification_prompt_comparison (
                            comparison_id, aggregate_run_id, package_id, field_key, field_label,
                            sealed_evidence_value, prompt_value, official_fact_value, state,
                            state_label, meaning, prompt_location, evidence_source,
                            recommended_owner, related_metric_codes, related_check_codes,
                            related_finding_ids, related_issue_ids, related_remediation_group_ids,
                            canonical_source, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                new Object[] {
                        fit("opc-" + UUID.randomUUID(), 256),
                        fit(command.aggregateRunId(), 256),
                        fit(command.packageId(), 256),
                        fit(comparison.fieldKey(), 512),
                        fit(comparison.fieldLabel(), 255),
                        command.sealedEvidenceDisplay(),
                        command.promptDisplay(),
                        command.officialFactDisplay(),
                        fit(defaultText(comparison.state(), "UNKNOWN"), 64),
                        fit(defaultText(comparison.stateLabel(), ""), 120),
                        defaultText(comparison.meaning(), ""),
                        fit(defaultText(comparison.promptLocation(), ""), 256),
                        fit(defaultText(comparison.evidenceSource(), ""), 512),
                        fit(defaultText(comparison.recommendedOwner(), ""), 128),
                        fit(String.join(",", comparison.metricCodes()), 512),
                        fit(String.join(",", comparison.checkCodes()), 2048),
                        fit(String.join(",", comparison.findingIds()), 2048),
                        fit(String.join(",", comparison.issueIds()), 2048),
                        fit(String.join(",", comparison.remediationGroupIds()), 4096),
                        fit(defaultText(comparison.canonicalSource(), "PROMPT_COMPARISON"), 64),
                        Timestamp.from(Instant.now())
                });
    }

    private String defaultText(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    private String fit(String value, int maxLength) {
        if (!StringUtils.hasText(value) || maxLength <= 0) {
            return value;
        }
        String trimmed = value.trim();
        return trimmed.length() <= maxLength ? trimmed : trimmed.substring(0, maxLength);
    }
}
