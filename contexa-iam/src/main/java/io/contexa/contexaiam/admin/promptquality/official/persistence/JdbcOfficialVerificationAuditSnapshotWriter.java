package io.contexa.contexaiam.admin.promptquality.official.persistence;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationAuditSnapshotWriter;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityCustomerSentencePolicy;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class JdbcOfficialVerificationAuditSnapshotWriter
        implements OfficialVerificationAuditSnapshotWriter {

    private static final int CUSTOMER_TEXT_MAX = 1200;

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public JdbcOfficialVerificationAuditSnapshotWriter(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @Override
    public void record(AuditSnapshotCommand command) {
        Objects.requireNonNull(command, "command");
        if (!StringUtils.hasText(command.aggregateRunId()) || !StringUtils.hasText(command.packageId())) {
            return;
        }
        if (!StringUtils.hasText(command.tenantId())) {
            throw new IllegalArgumentException("tenantId is required for official verification audit mutation.");
        }
        List<String> findings = customerSentences(
                "audit.blockingFindings", command.blockingFindings(), true);
        List<String> actions = customerSentences(
                "audit.nextActions", command.nextActions(), false);
        Map<String, Object> payload = new LinkedHashMap<>(
                command.payload() == null ? Map.of() : command.payload());
        payload.put("blockingFindings", findings);
        payload.put("nextActions", actions);
        try {
            deleteCurrent(command);
            insert(command, findings, actions, payload);
        }
        catch (DataAccessException exception) {
            throw new IllegalStateException(
                    "Official verification audit snapshot persistence failed: " + databaseMessage(exception),
                    exception);
        }
    }

    private void deleteCurrent(AuditSnapshotCommand command) {
        jdbcTemplate.update("""
                        delete from official_verification_audit_snapshot audit
                        using sealed_evidence_package sealed
                         where audit.aggregate_run_id = ?
                           and audit.package_id = ?
                           and sealed.package_id = audit.package_id
                           and sealed.tenant_id = ?
                        """,
                command.aggregateRunId().trim(),
                command.packageId().trim(),
                command.tenantId().trim());
    }

    private void insert(
            AuditSnapshotCommand command,
            List<String> findings,
            List<String> actions,
            Map<String, Object> payload) {
        jdbcTemplate.update("""
                        insert into official_verification_audit_snapshot (
                            snapshot_id, aggregate_run_id, package_id, certificate_id, case_id,
                            state, state_label, total_metric_count, failed_metric_count,
                            certificate_issued, prompt_hash, context_hash, blocking_findings_json,
                            next_actions_json, payload_json, created_by, diagnostic_catalog_version, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                fit("pqa-audit-" + command.packageId().trim() + "-" + command.aggregateRunId().trim(), 256),
                fit(command.aggregateRunId(), 256),
                fit(command.packageId(), 256),
                fit(command.certificateId(), 256),
                fit(command.caseId(), 256),
                fit(command.state(), 80),
                fit(command.stateLabel(), 120),
                command.totalMetricCount(),
                command.failedMetricCount(),
                command.certificateIssued(),
                fit(command.promptHash(), 160),
                fit(command.contextHash(), 160),
                writeJson(findings),
                writeJson(actions),
                writeJson(payload),
                fit(firstNonBlank(command.operatorId(), "runtime-pqa"), 128),
                OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                Timestamp.from(Instant.now()));
    }

    private List<String> customerSentences(
            String fieldName,
            List<String> values,
            boolean blockingFinding) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        int index = 0;
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                result.add(PromptQualityCustomerSentencePolicy.requireCustomerSentence(
                        fieldName + "[" + index + "]",
                        customerSentence(value, blockingFinding)));
            }
            index++;
        }
        return List.copyOf(result);
    }

    private String customerSentence(String value, boolean blockingFinding) {
        String candidate = value == null ? "" : value.trim();
        if (PromptQualityCustomerSentencePolicy.isCustomerSentence(candidate)) {
            return concise(candidate, CUSTOMER_TEXT_MAX);
        }
        throw new IllegalStateException(
                "ENGINE_CONTRACT_ERROR: Audit snapshot sentence is not DB-contract backed. fieldValue=" + candidate);
    }

    private String concise(String value, int maxLength) {
        String cleaned = value.trim().replaceAll("\\s+", " ").trim();
        if (cleaned.length() <= maxLength) {
            return cleaned;
        }
        int sentenceEnd = cleaned.lastIndexOf('.', maxLength - 1);
        return sentenceEnd >= Math.max(80, maxLength / 2)
                ? cleaned.substring(0, sentenceEnd + 1).trim()
                : cleaned.substring(0, maxLength).trim();
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        }
        catch (JsonProcessingException exception) {
            throw new IllegalStateException("Official verification audit payload serialization failed.", exception);
        }
    }

    private String fit(String value, int maxLength) {
        if (!StringUtils.hasText(value)) {
            return value;
        }
        String trimmed = value.trim();
        return trimmed.length() <= maxLength ? trimmed : trimmed.substring(0, maxLength);
    }

    private String firstNonBlank(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    private String databaseMessage(DataAccessException exception) {
        Throwable cause = exception.getMostSpecificCause();
        return cause == null || !StringUtils.hasText(cause.getMessage())
                ? exception.getMessage()
                : cause.getMessage();
    }
}
