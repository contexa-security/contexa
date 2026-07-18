package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationExecutionLockService.ExecutionRecord;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricExecutionStatus;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationExecutionLockService.*;

final class OfficialVerificationExecutionLockQueryRepository {

    private static final String EXECUTION_COLUMNS = """
            id, idempotency_key, base_idempotency_key, package_id, tenant_id, aggregate_run_id,
            revision_no, attempt_no, state, progress_percent, recoverable, retry_instruction,
            failure_reason, failure_stage, requested_by, reverification_reason, request_fingerprint_json,
            result_json, started_at, completed_at, failed_at, created_at, updated_at
            """;

    private final JdbcTemplate jdbcTemplate;

    OfficialVerificationExecutionLockQueryRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    Optional<ExecutionRecord> findLatestByPackageId(String tenantId, String packageId) {
        if (!StringUtils.hasText(tenantId) || !StringUtils.hasText(packageId)) {
            return Optional.empty();
        }
        try {
            return jdbcTemplate.query(
                    "select " + EXECUTION_COLUMNS + " from official_verification_execution_lock"
                            + " where tenant_id = ? and package_id = ? order by updated_at desc, id desc limit 1",
                    this::record,
                    trim(tenantId),
                    trim(packageId)
            ).stream().findFirst();
        }
        catch (DataAccessException ignored) {
            return Optional.empty();
        }
    }

    Optional<ExecutionRecord> findByAggregateRunId(String tenantId, String packageId, String aggregateRunId) {
        if (!StringUtils.hasText(tenantId)
                || !StringUtils.hasText(packageId)
                || !StringUtils.hasText(aggregateRunId)) {
            return Optional.empty();
        }
        try {
            return jdbcTemplate.query(
                    "select " + EXECUTION_COLUMNS + " from official_verification_execution_lock"
                            + " where tenant_id = ? and package_id = ? and aggregate_run_id = ?"
                            + " order by updated_at desc, id desc limit 1",
                    this::record,
                    trim(tenantId),
                    trim(packageId),
                    trim(aggregateRunId)
            ).stream().findFirst();
        }
        catch (DataAccessException ignored) {
            return Optional.empty();
        }
    }
    List<OfficialVerificationMetricExecutionStatus> metricStatuses(ExecutionRecord record) {
        if (record == null || record.id() < 0) {
            return List.of();
        }
        try {
            return jdbcTemplate.query("""
                            select metric_code, sequence_no, state, progress_percent, recoverable,
                                   failure_reason, retry_instruction, started_at, completed_at
                              from official_verification_metric_execution_ledger
                             where execution_lock_id = ?
                               and tenant_id = ?
                               and attempt_no = ?
                             order by sequence_no, metric_code
                            """,
                    (rs, rowNum) -> new OfficialVerificationMetricExecutionStatus(
                            rs.getString("metric_code"),
                            rs.getInt("sequence_no"),
                            rs.getString("state"),
                            rs.getInt("progress_percent"),
                            boxedBoolean(rs, "recoverable"),
                            rs.getString("failure_reason"),
                            rs.getString("retry_instruction"),
                            instant(rs.getTimestamp("started_at")),
                            instant(rs.getTimestamp("completed_at"))
                    ),
                    record.id(), record.tenantId(), record.attemptNo()
            );
        }
        catch (DataAccessException ignored) {
            return List.of();
        }
    }

    Optional<ExecutionRecord> queryByKey(String tenantId, String idempotencyKey) {
        return jdbcTemplate.query(
                "select " + EXECUTION_COLUMNS + " from official_verification_execution_lock"
                        + " where tenant_id = ? and idempotency_key = ?",
                this::record,
                trim(tenantId),
                trim(idempotencyKey)
        ).stream().findFirst();
    }

    Optional<ExecutionRecord> findRunningByPackageId(String tenantId, String packageId) {
        if (!StringUtils.hasText(tenantId) || !StringUtils.hasText(packageId)) {
            return Optional.empty();
        }
        return jdbcTemplate.query(
                "select " + EXECUTION_COLUMNS + " from official_verification_execution_lock"
                        + " where tenant_id = ? and package_id = ?"
                        + " and state in (?, ?, ?, ?, ?, ?, ?) order by created_at desc, id desc limit 1",
                this::record,
                trim(tenantId), trim(packageId),
                STATE_LOCK_ACQUIRED, STATE_EVIDENCE_LOADED, STATE_CONSISTENCY_CHECKED,
                STATE_PREFLIGHT_FINAL_PROMPT_CONTRACT, STATE_METRICS_RUNNING,
                STATE_METRIC_FAILED, STATE_SNAPSHOT_WRITING
        ).stream().findFirst();
    }

    ExecutionRecord latestRecord(ExecutionRecord record) {
        if (record == null || !StringUtils.hasText(record.idempotencyKey())) {
            return record;
        }
        return queryByKey(record.tenantId(), record.idempotencyKey()).orElse(record);
    }

    ExecutionRecord acquired(ExecutionRecord record, boolean acquired) {
        return new ExecutionRecord(
                record.id(), record.idempotencyKey(), record.baseIdempotencyKey(), record.packageId(),
                record.tenantId(), record.aggregateRunId(), record.revisionNo(), record.attemptNo(),
                record.state(), record.progressPercent(), record.recoverable(), record.retryInstruction(),
                record.failureReason(), record.failureStage(), record.requestedBy(), record.reverificationReason(),
                record.requestFingerprintJson(), record.resultJson(), record.startedAt(), record.completedAt(),
                record.failedAt(), record.createdAt(), record.updatedAt(), acquired
        );
    }

    private ExecutionRecord record(ResultSet rs, int rowNum) throws SQLException {
        return new ExecutionRecord(
                rs.getLong("id"),
                rs.getString("idempotency_key"),
                rs.getString("base_idempotency_key"),
                rs.getString("package_id"),
                rs.getString("tenant_id"),
                rs.getString("aggregate_run_id"),
                rs.getInt("revision_no"),
                rs.getInt("attempt_no"),
                rs.getString("state"),
                rs.getInt("progress_percent"),
                boxedBoolean(rs, "recoverable"),
                rs.getString("retry_instruction"),
                rs.getString("failure_reason"),
                rs.getString("failure_stage"),
                rs.getString("requested_by"),
                rs.getString("reverification_reason"),
                rs.getString("request_fingerprint_json"),
                rs.getString("result_json"),
                instant(rs.getTimestamp("started_at")),
                instant(rs.getTimestamp("completed_at")),
                instant(rs.getTimestamp("failed_at")),
                instant(rs.getTimestamp("created_at")),
                instant(rs.getTimestamp("updated_at")),
                false
        );
    }

    private Boolean boxedBoolean(ResultSet rs, String column) throws SQLException {
        boolean value = rs.getBoolean(column);
        return rs.wasNull() ? null : value;
    }

    private Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    private String trim(String value) {
        return value == null ? null : value.trim();
    }
}
