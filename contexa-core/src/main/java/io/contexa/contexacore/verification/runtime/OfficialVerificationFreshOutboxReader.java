package io.contexa.contexacore.verification.runtime;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public class OfficialVerificationFreshOutboxReader {

    private static final String DECISION_SQL = """
            select id, correlation_id, tenant_external_ref, payload_json, status, attempt_count,
                   next_attempt_at, last_error, delivered_at, created_at, updated_at
            from security_decision_forwarding_outbox
            where correlation_id = ?
            """;

    private static final String PROMPT_SQL = """
            select id, audit_id, correlation_id, tenant_external_ref, payload_json, status, attempt_count,
                   next_attempt_at, last_error, delivered_at, created_at, updated_at
            from prompt_context_audit_forwarding_outbox
            where correlation_id = ?
            order by id desc
            limit 1
            """;

    private final JdbcTemplate jdbcTemplate;

    public OfficialVerificationFreshOutboxReader(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Optional<SecurityDecisionForwardingOutboxRecord> findFreshDecisionOutbox(String correlationId) {
        if (jdbcTemplate == null || !StringUtils.hasText(correlationId)) {
            return Optional.empty();
        }
        List<SecurityDecisionForwardingOutboxRecord> rows = jdbcTemplate.query(
                DECISION_SQL,
                (resultSet, rowNum) -> mapDecisionRecord(resultSet),
                correlationId.trim()
        );
        return rows.stream().findFirst();
    }

    public Optional<PromptContextAuditForwardingOutboxRecord> findFreshPromptAuditOutbox(String correlationId) {
        if (jdbcTemplate == null || !StringUtils.hasText(correlationId)) {
            return Optional.empty();
        }
        List<PromptContextAuditForwardingOutboxRecord> rows = jdbcTemplate.query(
                PROMPT_SQL,
                (resultSet, rowNum) -> mapPromptRecord(resultSet),
                correlationId.trim()
        );
        return rows.stream().findFirst();
    }

    public Optional<PromptContextAuditForwardingOutboxRecord> awaitPromptAuditOutbox(
            String correlationId,
            Duration timeout,
            boolean requireLineage
    ) {
        Instant deadline = Instant.now().plus(timeout != null ? timeout : Duration.ofSeconds(30));
        PromptContextAuditForwardingOutboxRecord record = null;
        long backoffMs = 250L;
        long maxBackoffMs = 2000L;
        while (Instant.now().isBefore(deadline)) {
            record = findFreshPromptAuditOutbox(correlationId).orElse(record);
            if (record != null && (!requireLineage || hasPromptAuditLineage(record.getPayloadJson()))) {
                return Optional.of(record);
            }
            sleep(backoffMs);
            backoffMs = Math.min(maxBackoffMs, backoffMs * 2);
        }
        return Optional.ofNullable(record);
    }

    private SecurityDecisionForwardingOutboxRecord mapDecisionRecord(ResultSet resultSet) throws SQLException {
        return SecurityDecisionForwardingOutboxRecord.builder()
                .id(resultSet.getLong("id"))
                .correlationId(resultSet.getString("correlation_id"))
                .tenantExternalRef(resultSet.getString("tenant_external_ref"))
                .payloadJson(resultSet.getString("payload_json"))
                .status(resultSet.getString("status"))
                .attemptCount(integerValue(resultSet, "attempt_count"))
                .nextAttemptAt(localDateTime(resultSet, "next_attempt_at"))
                .lastError(resultSet.getString("last_error"))
                .deliveredAt(localDateTime(resultSet, "delivered_at"))
                .createdAt(localDateTime(resultSet, "created_at"))
                .updatedAt(localDateTime(resultSet, "updated_at"))
                .build();
    }

    private PromptContextAuditForwardingOutboxRecord mapPromptRecord(ResultSet resultSet) throws SQLException {
        return PromptContextAuditForwardingOutboxRecord.builder()
                .id(resultSet.getLong("id"))
                .auditId(resultSet.getString("audit_id"))
                .correlationId(resultSet.getString("correlation_id"))
                .tenantExternalRef(resultSet.getString("tenant_external_ref"))
                .payloadJson(resultSet.getString("payload_json"))
                .status(resultSet.getString("status"))
                .attemptCount(integerValue(resultSet, "attempt_count"))
                .nextAttemptAt(localDateTime(resultSet, "next_attempt_at"))
                .lastError(resultSet.getString("last_error"))
                .deliveredAt(localDateTime(resultSet, "delivered_at"))
                .createdAt(localDateTime(resultSet, "created_at"))
                .updatedAt(localDateTime(resultSet, "updated_at"))
                .build();
    }

    private Integer integerValue(ResultSet resultSet, String column) throws SQLException {
        int value = resultSet.getInt(column);
        return resultSet.wasNull() ? null : value;
    }

    private LocalDateTime localDateTime(ResultSet resultSet, String column) throws SQLException {
        return resultSet.getObject(column, LocalDateTime.class);
    }

    private boolean hasPromptAuditLineage(String payloadJson) {
        if (!StringUtils.hasText(payloadJson)) {
            return false;
        }
        return payloadJson.contains("\"correlationId\":\"")
                && payloadJson.contains("\"promptHash\":\"")
                && payloadJson.contains("\"templateKey\":\"");
    }

    private void sleep(long millis) {
        try {
            Thread.sleep(millis);
        }
        catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
        }
    }
}
