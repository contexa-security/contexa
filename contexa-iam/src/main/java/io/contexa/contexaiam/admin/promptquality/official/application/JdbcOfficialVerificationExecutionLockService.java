package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricExecutionStatus;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

public class JdbcOfficialVerificationExecutionLockService implements OfficialVerificationExecutionLockService {

    private static final int REQUESTED_PROGRESS = OfficialVerificationProgressPolicy.REQUEST_ACCEPTED;
    private static final int LOCK_PROGRESS = OfficialVerificationProgressPolicy.LOCK_ACQUIRED;
    private static final int METRICS_PROGRESS = OfficialVerificationProgressPolicy.METRICS_RUNNING;
    private static final int COMPLETED_PROGRESS = OfficialVerificationProgressPolicy.COMPLETED;

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private volatile Boolean postgresqlDatabase;

    public JdbcOfficialVerificationExecutionLockService(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public ExecutionRecord start(ExecutionRequest request) {
        if (request == null || !StringUtils.hasText(request.idempotencyKey())
                || !StringUtils.hasText(request.baseIdempotencyKey())
                || !StringUtils.hasText(request.packageId())) {
            throw new IllegalArgumentException("Official verification idempotency request is incomplete.");
        }
        Optional<ExecutionRecord> running = findRunningByPackageId(request.packageId());
        if (running.isPresent()
                && !request.idempotencyKey().equals(running.get().idempotencyKey())) {
            return acquired(running.get(), false);
        }
        if (request.forceReverification()) {
            if (!StringUtils.hasText(request.reverificationReason())) {
                throw new IllegalArgumentException("Forced official reverification requires a reverification reason.");
            }
            return startForcedRevision(request);
        }
        boolean inserted = insertExecutionLock(request, trim(request.idempotencyKey()), 1);
        if (inserted) {
            return queryByKey(request.idempotencyKey())
                    .map(record -> {
                        recordState(record, STATE_REQUESTED, REQUESTED_PROGRESS, "Official verification request was accepted.", null, null, null);
                        recordState(record, STATE_LOCK_ACQUIRED, LOCK_PROGRESS, "Official verification execution lock was acquired.", null, null, null);
                        return acquired(record, true);
                    })
                    .orElseThrow(() -> new IllegalStateException("Official verification execution lock was inserted but cannot be read."));
        }
        return queryByKey(request.idempotencyKey())
                .map(record -> {
                    ExecutionRecord replay = restartFinishedOrReplay(record);
                    if (!replay.acquired()) {
                        recordState(
                                record,
                                "DUPLICATE_BLOCKED",
                                record.progressPercent(),
                                "Duplicate official verification execution was blocked by the idempotency key.",
                                null,
                                null,
                                null);
                    }
                    return replay;
                })
                .orElseThrow(() -> new IllegalStateException("Official verification execution lock exists but cannot be read."));
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void transition(ExecutionRecord record, String state, int progressPercent, String message) {
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
                        """,
                trim(state),
                boundedProgress,
                nowTimestamp(),
                record.id());
        recordState(record, state, boundedProgress, message, null, null, null);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void markMetricsRunning(ExecutionRecord record, String aggregateRunId, List<String> metricCodes) {
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
                        trim(metricCode));
            }
        }
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void markMetricCompleted(ExecutionRecord record, String aggregateRunId, String metricCode, int progressPercent) {
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
                trim(metricCode).toUpperCase());
        if (updated == 0) {
            insertMetric(record, aggregateRunId, metricCode, 999, STATE_COMPLETED, boundedProgress, false, null, null, Instant.now(), Instant.now());
        }
        advanceOverallProgress(record, aggregateRunId, boundedProgress);
        recordState(latestRecord(record), STATE_METRICS_RUNNING, boundedProgress,
                "Official metric completed: " + trim(metricCode).toUpperCase(), false, null, null);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void markMetricFailed(
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
        int failedProgress = OfficialVerificationProgressPolicy.failureProgress(latestRecord(record).progressPercent());
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
                trim(metricCode).toUpperCase());
        if (updated == 0) {
            insertMetric(record, aggregateRunId, metricCode, 999, STATE_METRIC_FAILED, failedProgress,
                    recoverable, reason, retryInstruction, Instant.now(), Instant.now());
        }
        advanceOverallProgress(record, aggregateRunId, failedProgress);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void markCompleted(ExecutionRecord record, String aggregateRunId, RuntimeEvidenceVerificationRun result) {
        if (record == null || record.id() < 0) {
            return;
        }
        jdbcTemplate.update("""
                        update official_verification_execution_lock
                           set state = ?,
                               progress_percent = ?,
                               aggregate_run_id = ?,
                               result_json = ?,
                               completed_at = ?,
                               updated_at = ?,
                               recoverable = ?,
                               retry_instruction = ?,
                               failure_reason = ?,
                               failure_stage = ?
                          where id = ?
                         """,
                STATE_COMPLETED,
                COMPLETED_PROGRESS,
                trim(aggregateRunId),
                writeResult(result),
                nowTimestamp(),
                nowTimestamp(),
                false,
                null,
                null,
                null,
                record.id());
        recordState(latestRecord(record), STATE_COMPLETED, COMPLETED_PROGRESS,
                "Official verification completed and stored.", false, null, null);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void markFailed(ExecutionRecord record, Throwable failure, boolean recoverable, String retryInstruction) {
        if (record == null || record.id() < 0) {
            return;
        }
        ExecutionRecord latest = latestRecord(record);
        String failedStage = latest.state();
        String failureState = STATE_PREFLIGHT_FINAL_PROMPT_CONTRACT.equals(failedStage)
                ? STATE_OFFICIAL_VERIFICATION_PREFLIGHT_FAILED
                : recoverable ? STATE_FAILED_RECOVERABLE : STATE_FAILED_TERMINAL;
        int failedProgress = OfficialVerificationProgressPolicy.failureProgress(latest.progressPercent());
        String reason = failureMessage(failure);
        jdbcTemplate.update("""
                        update official_verification_execution_lock
                           set state = ?,
                               progress_percent = ?,
                               failed_at = ?,
                               updated_at = ?,
                               recoverable = ?,
                               retry_instruction = ?,
                               failure_reason = ?,
                               failure_stage = ?
                          where id = ?
                          """,
                failureState,
                failedProgress,
                nowTimestamp(),
                nowTimestamp(),
                recoverable,
                trim(retryInstruction),
                reason,
                trim(failedStage),
                record.id());
        markIncompleteMetricsFailed(record, null, failure, recoverable, retryInstruction, failedProgress);
        recordState(latestRecord(record), failureState, failedProgress,
                recoverable
                        ? "Official verification stopped before completion. The same evidence can be retried after the cause is corrected."
                        : "Official verification stopped because this evidence cannot be verified without collecting new evidence or resolving the prerequisite.",
                recoverable,
                reason,
                retryInstruction);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.SUPPORTS, readOnly = true)
    public Optional<RuntimeEvidenceVerificationRun> completedResult(ExecutionRecord record) {
        if (record == null || !StringUtils.hasText(record.resultJson())) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(objectMapper.readValue(record.resultJson(), RuntimeEvidenceVerificationRun.class));
        }
        catch (Exception exception) {
            throw new IllegalStateException("Stored official verification result cannot be read.", exception);
        }
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.SUPPORTS, readOnly = true)
    public Optional<ExecutionRecord> findLatestByPackageId(String packageId) {
        if (!StringUtils.hasText(packageId)) {
            return Optional.empty();
        }
        try {
            return jdbcTemplate.query("""
                            select id, idempotency_key, base_idempotency_key, package_id, aggregate_run_id,
                                    revision_no, attempt_no, state, progress_percent, recoverable, retry_instruction,
                                    failure_reason, failure_stage, requested_by, reverification_reason, request_fingerprint_json,
                                    result_json, started_at, completed_at, failed_at, created_at, updated_at
                              from official_verification_execution_lock
                             where package_id = ?
                             order by created_at desc, id desc
                             limit 1
                            """,
                    this::record,
                    trim(packageId)).stream().findFirst();
        }
        catch (DataAccessException ignored) {
            return Optional.empty();
        }
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void deleteFinishedExecutionsForPackages(List<String> packageIds) {
        Set<String> normalized = new LinkedHashSet<>();
        if (packageIds != null) {
            for (String packageId : packageIds) {
                if (StringUtils.hasText(packageId)) {
                    normalized.add(packageId.trim());
                }
            }
        }
        for (String packageId : normalized) {
            if (findRunningByPackageId(packageId).isPresent()) {
                continue;
            }
            jdbcTemplate.update(
                    "delete from official_verification_execution_state_history where package_id = ?",
                    packageId);
            jdbcTemplate.update(
                    "delete from official_verification_metric_execution_ledger where package_id = ?",
                    packageId);
            jdbcTemplate.update(
                    "delete from official_verification_execution_lock where package_id = ?",
                    packageId);
        }
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.SUPPORTS, readOnly = true)
    public List<OfficialVerificationMetricExecutionStatus> metricStatuses(ExecutionRecord record) {
        if (record == null || record.id() < 0) {
            return List.of();
        }
        try {
            return jdbcTemplate.query("""
                            select metric_code, sequence_no, state, progress_percent, recoverable,
                                   failure_reason, retry_instruction, started_at, completed_at
                              from official_verification_metric_execution_ledger
                             where execution_lock_id = ?
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
                            instant(rs.getTimestamp("completed_at"))),
                    record.id(),
                    record.attemptNo());
        }
        catch (DataAccessException ignored) {
            return List.of();
        }
    }

    private ExecutionRecord startForcedRevision(ExecutionRequest request) {
        for (int attempt = 0; attempt < 3; attempt++) {
            int revision = nextRevision(request.baseIdempotencyKey());
            String revisionKey = request.baseIdempotencyKey() + ":rev:" + revision;
            boolean inserted = insertExecutionLock(request, revisionKey, revision);
            if (inserted) {
                return queryByKey(revisionKey)
                        .map(record -> {
                            recordState(record, STATE_REQUESTED, REQUESTED_PROGRESS, "Forced official reverification request was accepted.", null, null, null);
                            recordState(record, STATE_LOCK_ACQUIRED, LOCK_PROGRESS, "Forced official reverification execution lock was acquired.", null, null, null);
                            return acquired(record, true);
                        })
                        .orElseThrow(() -> new IllegalStateException("Forced official verification revision was inserted but cannot be read."));
            }
        }
        throw new IllegalStateException("Forced official verification revision could not acquire a unique execution lock.");
    }

    private int nextRevision(String baseIdempotencyKey) {
        Integer next = jdbcTemplate.queryForObject("""
                        select coalesce(max(revision_no), 0) + 1
                          from official_verification_execution_lock
                         where base_idempotency_key = ?
                        """,
                Integer.class,
                trim(baseIdempotencyKey));
        return next == null || next < 2 ? 2 : next;
    }

    private Optional<ExecutionRecord> queryByKey(String idempotencyKey) {
        return jdbcTemplate.query("""
                        select id, idempotency_key, base_idempotency_key, package_id, aggregate_run_id,
                                revision_no, attempt_no, state, progress_percent, recoverable, retry_instruction,
                                failure_reason, failure_stage, requested_by, reverification_reason, request_fingerprint_json,
                                result_json, started_at, completed_at, failed_at, created_at, updated_at
                          from official_verification_execution_lock
                         where idempotency_key = ?
                        """,
                this::record,
                trim(idempotencyKey)).stream().findFirst();
    }

    private Optional<ExecutionRecord> findRunningByPackageId(String packageId) {
        if (!StringUtils.hasText(packageId)) {
            return Optional.empty();
        }
        return jdbcTemplate.query("""
                        select id, idempotency_key, base_idempotency_key, package_id, aggregate_run_id,
                                revision_no, attempt_no, state, progress_percent, recoverable, retry_instruction,
                                failure_reason, failure_stage, requested_by, reverification_reason, request_fingerprint_json,
                                result_json, started_at, completed_at, failed_at, created_at, updated_at
                          from official_verification_execution_lock
                         where package_id = ?
                           and state in (?, ?, ?, ?, ?, ?)
                         order by updated_at desc, id desc
                         limit 1
                        """,
                this::record,
                trim(packageId),
                STATE_LOCK_ACQUIRED,
                STATE_EVIDENCE_LOADED,
                STATE_CONSISTENCY_CHECKED,
                STATE_METRICS_RUNNING,
                STATE_METRIC_FAILED,
                STATE_SNAPSHOT_WRITING).stream().findFirst();
    }

    private ExecutionRecord record(ResultSet rs, int rowNum) throws SQLException {
        return new ExecutionRecord(
                rs.getLong("id"),
                rs.getString("idempotency_key"),
                rs.getString("base_idempotency_key"),
                rs.getString("package_id"),
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
                false);
    }

    private ExecutionRecord acquired(ExecutionRecord record, boolean acquired) {
        return new ExecutionRecord(
                record.id(),
                record.idempotencyKey(),
                record.baseIdempotencyKey(),
                record.packageId(),
                record.aggregateRunId(),
                record.revisionNo(),
                record.attemptNo(),
                record.state(),
                record.progressPercent(),
                record.recoverable(),
                record.retryInstruction(),
                record.failureReason(),
                record.failureStage(),
                record.requestedBy(),
                record.reverificationReason(),
                record.requestFingerprintJson(),
                record.resultJson(),
                record.startedAt(),
                record.completedAt(),
                record.failedAt(),
                record.createdAt(),
                record.updatedAt(),
                acquired);
    }

    private ExecutionRecord restartFinishedOrReplay(ExecutionRecord record) {
        if (record == null || record.running()) {
            return acquired(record, false);
        }
        if (!record.completed() && !record.failed()) {
            return acquired(record, false);
        }
        jdbcTemplate.update(
                "delete from official_verification_execution_state_history where execution_lock_id = ?",
                record.id());
        jdbcTemplate.update(
                "delete from official_verification_metric_execution_ledger where execution_lock_id = ?",
                record.id());
        int updated = jdbcTemplate.update("""
                        update official_verification_execution_lock
                           set attempt_no = 1,
                               state = ?,
                               progress_percent = ?,
                               aggregate_run_id = ?,
                               recoverable = ?,
                               retry_instruction = ?,
                               failure_reason = ?,
                               failure_stage = ?,
                               result_json = ?,
                               started_at = ?,
                               completed_at = ?,
                               failed_at = ?,
                               updated_at = ?
                         where id = ?
                        """,
                STATE_LOCK_ACQUIRED,
                LOCK_PROGRESS,
                null,
                null,
                null,
                null,
                null,
                null,
                nowTimestamp(),
                null,
                null,
                nowTimestamp(),
                record.id());
        if (updated != 1) {
            return queryByKey(record.idempotencyKey())
                    .map(existing -> acquired(existing, false))
                    .orElseGet(() -> acquired(record, false));
        }
        ExecutionRecord retry = queryByKey(record.idempotencyKey())
                .orElse(record);
        recordState(retry, STATE_REQUESTED, REQUESTED_PROGRESS,
                "Previous official verification diagnostic data was replaced by a new run for the same quality target.",
                null,
                null,
                null);
        recordState(retry, STATE_LOCK_ACQUIRED, LOCK_PROGRESS,
                "Official verification execution lock was reacquired for the latest diagnostic run.",
                null,
                null,
                null);
        return acquired(retry, true);
    }

    private boolean insertExecutionLock(ExecutionRequest request, String idempotencyKey, int revision) {
        String sql = """
                        insert into official_verification_execution_lock (
                            idempotency_key, base_idempotency_key, package_id, revision_no,
                            attempt_no, state, progress_percent, requested_by, reverification_reason,
                            request_fingerprint_json, started_at, created_at, updated_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """ + postgresqlConflictClause("idempotency_key");
        try {
            int inserted = jdbcTemplate.update(
                    sql,
                    trim(idempotencyKey),
                    trim(request.baseIdempotencyKey()),
                    trim(request.packageId()),
                    revision,
                    1,
                    STATE_LOCK_ACQUIRED,
                    LOCK_PROGRESS,
                    trim(request.requestedBy()),
                    trim(request.reverificationReason()),
                    request.requestFingerprintJson(),
                    nowTimestamp(),
                    nowTimestamp(),
                    nowTimestamp());
            return inserted > 0;
        }
        catch (DuplicateKeyException duplicate) {
            return false;
        }
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
                                execution_lock_id, package_id, aggregate_run_id, attempt_no,
                                metric_code, sequence_no, state, progress_percent,
                                recoverable, failure_reason, retry_instruction,
                                started_at, completed_at, created_at, updated_at
                            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """ + postgresqlConflictClause("execution_lock_id, attempt_no, metric_code");
        try {
            int inserted = jdbcTemplate.update(
                    sql,
                    record.id(),
                    trim(record.packageId()),
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

    private void markIncompleteMetricsFailed(
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
                STATE_COMPLETED);
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
                        """,
                boundedProgress,
                boundedProgress,
                trim(aggregateRunId),
                nowTimestamp(),
                record.id());
    }

    private void recordState(
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
                            execution_lock_id, package_id, aggregate_run_id, attempt_no,
                            state, progress_percent, recoverable, failure_stage,
                            failure_reason, retry_instruction, message, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                record.id(),
                trim(record.packageId()),
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

    private ExecutionRecord latestRecord(ExecutionRecord record) {
        if (record == null || !StringUtils.hasText(record.idempotencyKey())) {
            return record;
        }
        return queryByKey(record.idempotencyKey()).orElse(record);
    }

    private String writeResult(RuntimeEvidenceVerificationRun result) {
        if (result == null) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(result);
        }
        catch (Exception exception) {
            throw new IllegalStateException("Official verification result cannot be serialized for idempotent replay.", exception);
        }
    }

    private String failureMessage(Throwable failure) {
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

    private Boolean boxedBoolean(ResultSet rs, String column) throws SQLException {
        boolean value = rs.getBoolean(column);
        return rs.wasNull() ? null : value;
    }

    private Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    private Timestamp nowTimestamp() {
        return Timestamp.from(Instant.now());
    }

    private Timestamp timestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    private String postgresqlConflictClause(String columnExpression) {
        return postgresqlDatabase() ? " on conflict (" + columnExpression + ") do nothing" : "";
    }

    private boolean postgresqlDatabase() {
        Boolean cached = postgresqlDatabase;
        if (cached != null) {
            return cached;
        }
        try {
            String productName = jdbcTemplate.execute((ConnectionCallback<String>) connection ->
                    connection.getMetaData().getDatabaseProductName());
            boolean detected = productName != null
                    && productName.toLowerCase(Locale.ROOT).contains("postgresql");
            postgresqlDatabase = detected;
            return detected;
        }
        catch (DataAccessException exception) {
            postgresqlDatabase = false;
            return false;
        }
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
