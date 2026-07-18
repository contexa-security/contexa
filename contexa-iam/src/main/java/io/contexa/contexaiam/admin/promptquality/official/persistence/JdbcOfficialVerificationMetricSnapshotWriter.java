package io.contexa.contexaiam.admin.promptquality.official.persistence;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationMetricSnapshotWriter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;

public final class JdbcOfficialVerificationMetricSnapshotWriter
        implements OfficialVerificationMetricSnapshotWriter {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public JdbcOfficialVerificationMetricSnapshotWriter(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @Override
    public void insert(MetricSnapshotCommand command) {
        Objects.requireNonNull(command, "command");
        MetricIdentity identity = Objects.requireNonNull(command.identity(), "identity");
        MetricAssessment assessment = Objects.requireNonNull(command.assessment(), "assessment");
        OperatorNarrative narrative = Objects.requireNonNull(command.narrative(), "narrative");
        jdbcTemplate.update("""
                        insert into official_verification_metric_snapshot (
                            aggregate_run_id, official_run_id, package_id, certificate_id, case_id,
                            metric_code, metric_name, metric_group, score, state, severity,
                            passed_checks, total_checks, failed_check_count, operator_title,
                            operator_summary, primary_failure_reason, remediation_owner,
                            next_action, reverify_criterion, issue_ids_json, problem_ids_json,
                            diagnostic_catalog_version, current_result, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                fit(identity.aggregateRunId(), 256),
                fit(identity.officialRunId(), 256),
                fit(identity.packageId(), 256),
                fit(identity.certificateId(), 256),
                fit(identity.caseId(), 256),
                fit(identity.metricCode(), 32),
                fit(identity.metricName(), 255),
                fit(identity.metricGroup(), 128),
                assessment.score(),
                fit(assessment.state(), 80),
                fit(assessment.severity(), 32),
                assessment.passedChecks(),
                assessment.totalChecks(),
                assessment.failedCheckCount(),
                fit(narrative.title(), 255),
                narrative.summary(),
                narrative.primaryFailureReason(),
                fit(narrative.remediationOwner(), 128),
                narrative.nextAction(),
                narrative.reverifyCriterion(),
                writeJson(command.issueIds()),
                writeJson(command.problemIds()),
                OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                true,
                Timestamp.from(Instant.now()));
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        }
        catch (JsonProcessingException exception) {
            throw new IllegalStateException("Official verification metric snapshot serialization failed.", exception);
        }
    }

    private String fit(String value, int maxLength) {
        if (!StringUtils.hasText(value) || maxLength <= 0) {
            return value;
        }
        String trimmed = value.trim();
        return trimmed.length() <= maxLength ? trimmed : trimmed.substring(0, maxLength);
    }
}
