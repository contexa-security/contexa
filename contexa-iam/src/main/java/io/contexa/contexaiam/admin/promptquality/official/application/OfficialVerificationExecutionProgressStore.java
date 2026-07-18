package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationExecutionLockService.ExecutionRecord;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

import static io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationExecutionLockService.*;

final class OfficialVerificationExecutionProgressStore {

    private static final int METRICS_PROGRESS = OfficialVerificationProgressPolicy.METRICS_RUNNING;
    private final JdbcTemplate jdbcTemplate;
    private final OfficialVerificationExecutionLockQueryRepository queryRepository;

    OfficialVerificationExecutionProgressStore(
            JdbcTemplate jdbcTemplate,
            OfficialVerificationExecutionLockQueryRepository queryRepository
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.queryRepository = queryRepository;
    }

    void deleteProgressForPackage(String tenantId, String packageId) {
        jdbcTemplate.update(
                "delete from official_verification_execution_state_history where package_id = ? and tenant_id = ?",
                packageId, tenantId
        );
        jdbcTemplate.update(
                "delete from official_verification_metric_execution_ledger where package_id = ? and tenant_id = ?",
                packageId, tenantId
        );
    }
    void transition(ExecutionRecord record, String state, int progressPercent, String message) {
        if (record == null || record.id() < 0 || !StringUtils.hasText(state)) {
            return;
        }
        int boundedProgress = OfficialVerificationProgressPolicy.bound(progressPercent);
        jdbcTemplate.update("""
                        update official_verification_execution_lock
                           set state = ?,
                               progress_percent = ?,
                               updated_at = ?
                         where id = ?
                           and tenant_id = ?
                        """,
                trim(state),
                boundedProgress,
                nowTimestamp(),
                record.id(),
                record.tenantId());
        recordState(record, state, boundedProgress, message, null, null, null);
    }

    void markMetricsRunning(ExecutionRecord record, String aggregateRunId, List<String> metricCodes) {
        if (record == null || record.id() < 0) {
            return;
        }
        transition(record, STATE_METRICS_RUNNING, METRICS_PROGRESS, "Official prompt quality metrics started.");
        List<String> normalized = metricCodes == null ? List.of() : metricCodes.stream()
                .filter(StringUtils::hasText)
                .map(value -> value.trim().toUpperCase())
                .distinct()
                .toList();
        int sequence = 1;
        for (String metricCode : normalized) {
            int currentSequence = sequence++;
            boolean inserted = insertMetricLedger(
                    record,
                    aggregateRunId,
                    metricCode,
                    currentSequence,
                    STATE_METRICS_RUNNING,
                    METRICS_PROGRESS,
                    null,
                    null,
                    null,
                    Instant.now(),
                    null);
            if (!inserted) {
                jdbcTemplate.update("""
                                update official_verification_metric_execution_ledger
                                   set state = ?,
                                       progress_percent = ?,
                                       aggregate_run_id = ?,
                                       failure_reason = ?,
                                       retry_instruction = ?,
                                       recoverable = ?,
                                       started_at = coalesce(started_at, ?),
                                       completed_at = ?,
                                       updated_at = ?
                                 where execution_lock_id = ?
                                   and attempt_no = ?
                                   and metric_code = ?
                                   and tenant_id = ?
                                """,
                        STATE_METRICS_RUNNING,
                        METRICS_PROGRESS,
                        trim(aggregateRunId),
                        null,
                        null,
                        null,
                        nowTimestamp(),
                        null,
                        nowTimestamp(),
                        record.id(),
                        record.attemptNo(),
                        trim(metricCode),
                        record.tenantId());
            }
        }
    }

    void markMetricCompleted(ExecutionRecord record, String aggregateRunId, String metricCode, int progressPercent) {
        if (record == null || record.id() < 0 || !StringUtils.hasText(metricCode)) {
            return;
        }
        int boundedProgress = OfficialVerificationProgressPolicy.bound(progressPercent);
        int updated = jdbcTemplate.update("""
                        update official_verification_metric_execution_ledger
                           set state = ?,
                               progress_percent = ?,
                               aggregate_run_id = ?,
                               completed_at = ?,
                               recoverable = ?,
                               failure_reason = ?,
                               retry_instruction = ?,
                               updated_at = ?
                         where execution_lock_id = ?
                           and attempt_no = ?
                           and metric_code = ?
                           and tenant_id = ?
                        """,
                STATE_COMPLETED,
                boundedProgress,
                trim(aggregateRunId),
                nowTimestamp(),
                false,
                null,
                null,
                nowTimestamp(),
                record.id(),
                record.attemptNo(),
                trim(metricCode).toUpperCase(),
                record.tenantId());
        if (updated == 0) {
            insertMetric(record, aggregateRunId, metricCode, 999, STATE_COMPLETED, boundedProgress, false, null, null, Instant.now(), Instant.now());
        }
        advanceOverallProgress(record, aggregateRunId, boundedProgress);
        recordState(queryRepository.latestRecord(record), STATE_METRICS_RUNNING, boundedProgress,
                "Official metric completed: " + trim(metricCode).toUpperCase(), false, null, null);
    }

    void markMetricFailed(
            ExecutionRecord record,
            String aggregateRunId,
            String metricCode,
            Throwable failure,
            boolean recoverable,
            String retryInstruction) {
        if (record == null || record.id() < 0 || !StringUtils.hasText(metricCode)) {
            return;
        }
        String reason = failureMessage(failure);
        int failedProgress = OfficialVerificationProgressPolicy.failureProgress(queryRepository.latestRecord(record).progressPercent());
        int updated = jdbcTemplate.update("""
                        update official_verification_metric_execution_ledger
                           set state = ?,
                               progress_percent = ?,
                               aggregate_run_id = ?,
                               completed_at = ?,
                               recoverable = ?,
                               failure_reason = ?,
                               retry_instruction = ?,
                               updated_at = ?
                         where execution_lock_id = ?
                           and attempt_no = ?
                           and metric_code = ?
                           and tenant_id = ?
                        """,
                STATE_METRIC_FAILED,
                failedProgress,
                trim(aggregateRunId),
                nowTimestamp(),
                recoverable,
                reason,
                trim(retryInstruction),
                nowTimestamp(),
                record.id(),
                record.attemptNo(),
                trim(metricCode).toUpperCase(),
                record.tenantId());
        if (updated == 0) {
            insertMetric(record, aggregateRunId, metricCode, 999, STATE_METRIC_FAILED, failedProgress,
                    recoverable, reason, retryInstruction, Instant.now(), Instant.now());
        }
        advanceOverallProgress(record, aggregateRunId, failedProgress);
    }

    private void insertMetric(
            ExecutionRecord record,
            String aggregateRunId,
            String metricCode,
            int sequenceNo,
            String state,
            int progressPercent,
            Boolean recoverable,
            String failureReason,
            String retryInstruction,
            Instant startedAt,
            Instant completedAt) {
        insertMetricLedger(
                record,
                aggregateRunId,
                metricCode,
                sequenceNo,
                state,
                progressPercent,
                recoverable,
                failureReason,
                retryInstruction,
                startedAt,
                completedAt);
    }

    private boolean insertMetricLedger(
            ExecutionRecord record,
            String aggregateRunId,
            String metricCode,
            int sequenceNo,
            String state,
            int progressPercent,
            Boolean recoverable,
            String failureReason,
            String retryInstruction,
            Instant startedAt,
            Instant completedAt) {
        String sql = """
                            insert into official_verification_metric_execution_ledger (
                                execution_lock_id, package_id, tenant_id, aggregate_run_id, attempt_no,
                                metric_code, sequence_no, state, progress_percent,
                                recoverable, failure_reason, retry_instruction,
                                started_at, completed_at, created_at, updated_at
                            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """ + postgresqlConflictClause("execution_lock_id, attempt_no, metric_code");
        try {
            int inserted = jdbcTemplate.update(
                    sql,
                    record.id(),
                    trim(record.packageId()),
                    trim(record.tenantId()),
                    trim(aggregateRunId),
                    record.attemptNo(),
                    trim(metricCode).toUpperCase(),
                    sequenceNo,
                    trim(state),
                    OfficialVerificationProgressPolicy.bound(progressPercent),
                    recoverable,
                    trim(failureReason),
                    trim(retryInstruction),
                    timestamp(startedAt),
                    timestamp(completedAt),
                    nowTimestamp(),
                    nowTimestamp());
            return inserted > 0;
        }
        catch (DuplicateKeyException ignored) {
            return false;
        }
    }

    void markIncompleteMetricsFailed(
            ExecutionRecord record,
            String aggregateRunId,
            Throwable failure,
            boolean recoverable,
            String retryInstruction,
            int failedProgress) {
        String reason = failureMessage(failure);
        jdbcTemplate.update("""
                        update official_verification_metric_execution_ledger
                           set state = ?,
                               progress_percent = ?,
                               aggregate_run_id = coalesce(aggregate_run_id, ?),
                               completed_at = coalesce(completed_at, ?),
                               recoverable = ?,
                               failure_reason = coalesce(failure_reason, ?),
                               retry_instruction = coalesce(retry_instruction, ?),
                               updated_at = ?
                         where execution_lock_id = ?
                           and attempt_no = ?
                           and state <> ?
                           and tenant_id = ?
                """,
                STATE_METRIC_FAILED,
                OfficialVerificationProgressPolicy.failureProgress(failedProgress),
                trim(aggregateRunId),
                nowTimestamp(),
                recoverable,
                reason,
                trim(retryInstruction),
                nowTimestamp(),
                record.id(),
                record.attemptNo(),
                STATE_COMPLETED,
                record.tenantId());
    }

    private void advanceOverallProgress(ExecutionRecord record, String aggregateRunId, int progressPercent) {
        if (record == null || record.id() < 0) {
            return;
        }
        int boundedProgress = OfficialVerificationProgressPolicy.bound(progressPercent);
        jdbcTemplate.update("""
                        update official_verification_execution_lock
                           set progress_percent = case when progress_percent < ? then ? else progress_percent end,
                               aggregate_run_id = coalesce(aggregate_run_id, ?),
                               updated_at = ?
                         where id = ?
                           and tenant_id = ?
                        """,
                boundedProgress,
                boundedProgress,
                trim(aggregateRunId),
                nowTimestamp(),
                record.id(),
                record.tenantId());
    }

    void recordState(
            ExecutionRecord record,
            String state,
            int progressPercent,
            String message,
            Boolean recoverable,
            String failureReason,
            String retryInstruction) {
        if (record == null || record.id() < 0 || !StringUtils.hasText(state)) {
            return;
        }
        jdbcTemplate.update("""
                        insert into official_verification_execution_state_history (
                            execution_lock_id, package_id, tenant_id, aggregate_run_id, attempt_no,
                            state, progress_percent, recoverable, failure_stage,
                            failure_reason, retry_instruction, message, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                record.id(),
                trim(record.packageId()),
                trim(record.tenantId()),
                trim(record.aggregateRunId()),
                record.attemptNo(),
                trim(state),
                OfficialVerificationProgressPolicy.bound(progressPercent),
                recoverable,
                trim(record.failureStage()),
                trim(failureReason),
                trim(retryInstruction),
                trim(message),
                nowTimestamp());
    }

    String failureMessage(Throwable failure) {
        if (failure == null) {
            return "Official verification stopped before completion.";
        }
        if (!StringUtils.hasText(failure.getMessage())) {
            return fit("Official verification stopped before completion. error="
                    + failure.getClass().getSimpleName() + firstApplicationFrame(failure), 2000);
        }
        String message = failure.getMessage().trim();
        if (message.contains("\n")
                || message.contains("\tat ")
                || message.contains("org.springframework.")
                || message.contains("java.lang.")
                || message.contains("jakarta.persistence.")
                || message.contains("PreparedStatementCallback")) {
            return "Official verification stopped because a runtime or database error occurred. Check the execution status ledger, database schema, column lengths, and official metric engine configuration.";
        }
        return fit(message, 2000);
    }

    private String firstApplicationFrame(Throwable failure) {
        if (failure == null || failure.getStackTrace() == null) {
            return "";
        }
        for (StackTraceElement frame : failure.getStackTrace()) {
            if (frame != null && frame.getClassName() != null
                    && frame.getClassName().startsWith("io.contexa.")) {
                return ", location=" + frame.getClassName() + ":" + frame.getLineNumber();
            }
        }
        StackTraceElement[] frames = failure.getStackTrace();
        if (frames.length == 0 || frames[0] == null) {
            return "";
        }
        return ", location=" + frames[0].getClassName() + ":" + frames[0].getLineNumber();
    }

    private Timestamp nowTimestamp() {
        return Timestamp.from(Instant.now());
    }

    private Timestamp timestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    private String postgresqlConflictClause(String columnExpression) {
        return " on conflict (" + columnExpression + ") do nothing";
    }
    private String trim(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }

    private String fit(String value, int maxLength) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.length() <= maxLength ? trimmed : trimmed.substring(0, maxLength);
    }
}
