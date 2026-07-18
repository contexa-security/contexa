package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationRunBatchWriter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;

public final class JdbcOfficialVerificationRunBatchWriter implements OfficialVerificationRunBatchWriter {

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationRunBatchWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void insert(RunBatchCommand command) {
        Objects.requireNonNull(command, "command");
        MetricCounts counts = Objects.requireNonNull(command.metricCounts(), "metricCounts");
        EvidenceIdentity evidence = Objects.requireNonNull(command.evidenceIdentity(), "evidenceIdentity");
        Timestamp occurredAt = Timestamp.from(Instant.now());
        jdbcTemplate.update("""
                        insert into official_verification_run_batch (
                            aggregate_run_id, package_id, tenant_id, certificate_id, case_id, scope_type,
                            expected_metric_count, actual_metric_count, passed_metric_count,
                            failed_metric_count, insufficient_metric_count, not_applicable_metric_count,
                            final_decision, blocked, block_reason_summary, prompt_hash, context_hash,
                            context_hash_state, template_resource_id, actual_resource_id,
                            resource_url_template, actual_request_path, http_method,
                            started_at, completed_at, diagnostic_catalog_version, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                fit(command.aggregateRunId(), 256),
                fit(command.packageId(), 256),
                fit(command.tenantId(), 120),
                fit(command.certificateId(), 256),
                fit(command.caseId(), 256),
                "PROMPT_QUALITY",
                counts.total(),
                counts.total(),
                counts.passed(),
                counts.failed(),
                counts.insufficient(),
                counts.notApplicable(),
                command.finalDecision(),
                command.blocked(),
                command.blockReasonSummary(),
                fit(evidence.promptHash(), 160),
                fit(evidence.contextHash(), 160),
                fit(evidence.contextHashState(), 64),
                fit(evidence.templateResourceId(), 256),
                fit(evidence.actualResourceId(), 256),
                evidence.resourceUrlTemplate(),
                evidence.actualRequestPath(),
                fit(evidence.httpMethod(), 32),
                occurredAt,
                occurredAt,
                OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                occurredAt);
    }

    private String fit(String value, int maxLength) {
        if (!StringUtils.hasText(value) || maxLength <= 0) {
            return value;
        }
        String trimmed = value.trim();
        return trimmed.length() <= maxLength ? trimmed : trimmed.substring(0, maxLength);
    }
}
