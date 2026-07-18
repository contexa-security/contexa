package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricExecutionStatus;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class JdbcOfficialVerificationExecutionLockService implements OfficialVerificationExecutionLockService {

    private static final int REQUESTED_PROGRESS = OfficialVerificationProgressPolicy.REQUEST_ACCEPTED;
    private static final int LOCK_PROGRESS = OfficialVerificationProgressPolicy.LOCK_ACQUIRED;
    private static final int METRICS_PROGRESS = OfficialVerificationProgressPolicy.METRICS_RUNNING;
    private static final int COMPLETED_PROGRESS = OfficialVerificationProgressPolicy.COMPLETED;

    private final JdbcTemplate jdbcTemplate;
    private final OfficialVerificationExecutionLockQueryRepository queryRepository;
    private final OfficialVerificationExecutionProgressStore progressStore;
    private final OfficialVerificationExecutionLockLifecycleStore lifecycleStore;
    private final ObjectMapper objectMapper;
    private final Duration staleExecutionTimeout;

    public JdbcOfficialVerificationExecutionLockService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            Duration staleExecutionTimeout) {
        if (staleExecutionTimeout == null || staleExecutionTimeout.isZero() || staleExecutionTimeout.isNegative()) {
            throw new IllegalArgumentException("Official verification stale execution timeout must be positive.");
        }
        this.jdbcTemplate = jdbcTemplate;
        this.queryRepository = new OfficialVerificationExecutionLockQueryRepository(jdbcTemplate);
        this.progressStore = new OfficialVerificationExecutionProgressStore(jdbcTemplate, queryRepository);
        this.lifecycleStore = new OfficialVerificationExecutionLockLifecycleStore(
                jdbcTemplate, queryRepository, progressStore
        );
        this.objectMapper = objectMapper;
        this.staleExecutionTimeout = staleExecutionTimeout;
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public ExecutionRecord start(ExecutionRequest request) {
        if (request == null || !StringUtils.hasText(request.idempotencyKey())
                || !StringUtils.hasText(request.baseIdempotencyKey())
                || !StringUtils.hasText(request.packageId())
                || !StringUtils.hasText(request.tenantId())) {
            throw new IllegalArgumentException("Official verification idempotency request is incomplete.");
        }
        recoverStaleExecution(request.tenantId(), request.packageId());
        Optional<ExecutionRecord> running = queryRepository.findRunningByPackageId(request.tenantId(), request.packageId());
        if (running.isPresent()
                && !request.idempotencyKey().equals(running.get().idempotencyKey())) {
            return queryRepository.acquired(running.get(), false);
        }
        if (request.forceReverification()) {
            if (!StringUtils.hasText(request.reverificationReason())) {
                throw new IllegalArgumentException("Forced official reverification requires a reverification reason.");
            }
            return lifecycleStore.startForcedRevision(request);
        }
        boolean inserted = lifecycleStore.insertExecutionLock(request, trim(request.idempotencyKey()), 1);
        if (inserted) {
            return queryRepository.queryByKey(request.tenantId(), request.idempotencyKey())
                    .map(record -> {
                        progressStore.recordState(record, STATE_REQUESTED, REQUESTED_PROGRESS, "Official verification request was accepted.", null, null, null);
                        progressStore.recordState(record, STATE_LOCK_ACQUIRED, LOCK_PROGRESS, "Official verification execution lock was acquired.", null, null, null);
                        return queryRepository.acquired(record, true);
                    })
                    .orElseThrow(() -> new IllegalStateException("Official verification execution lock was inserted but cannot be read."));
        }
        return queryRepository.queryByKey(request.tenantId(), request.idempotencyKey())
                .map(record -> {
                    ExecutionRecord replay = lifecycleStore.restartFinishedOrReplay(record);
                    if (!replay.acquired()) {
                        progressStore.recordState(
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
        progressStore.transition(record, state, progressPercent, message);
    }
    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void markMetricsRunning(ExecutionRecord record, String aggregateRunId, List<String> metricCodes) {
        progressStore.markMetricsRunning(record, aggregateRunId, metricCodes);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void markMetricCompleted(ExecutionRecord record, String aggregateRunId, String metricCode, int progressPercent) {
        progressStore.markMetricCompleted(record, aggregateRunId, metricCode, progressPercent);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void markMetricFailed(
            ExecutionRecord record,
            String aggregateRunId,
            String metricCode,
            Throwable failure,
            boolean recoverable,
            String retryInstruction
    ) {
        progressStore.markMetricFailed(record, aggregateRunId, metricCode, failure, recoverable, retryInstruction);
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
                           and tenant_id = ?
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
                record.id(),
                record.tenantId());
        progressStore.recordState(queryRepository.latestRecord(record), STATE_COMPLETED, COMPLETED_PROGRESS,
                "Official verification completed and stored.", false, null, null);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void markFailed(ExecutionRecord record, Throwable failure, boolean recoverable, String retryInstruction) {
        if (record == null || record.id() < 0) {
            return;
        }
        ExecutionRecord latest = queryRepository.latestRecord(record);
        String failedStage = latest.state();
        String failureState = STATE_PREFLIGHT_FINAL_PROMPT_CONTRACT.equals(failedStage)
                ? STATE_OFFICIAL_VERIFICATION_PREFLIGHT_FAILED
                : recoverable ? STATE_FAILED_RECOVERABLE : STATE_FAILED_TERMINAL;
        int failedProgress = OfficialVerificationProgressPolicy.failureProgress(latest.progressPercent());
        String reason = progressStore.failureMessage(failure);
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
                           and tenant_id = ?
                          """,
                failureState,
                failedProgress,
                nowTimestamp(),
                nowTimestamp(),
                recoverable,
                trim(retryInstruction),
                reason,
                trim(failedStage),
                record.id(),
                record.tenantId());
        progressStore.markIncompleteMetricsFailed(record, null, failure, recoverable, retryInstruction, failedProgress);
        progressStore.recordState(queryRepository.latestRecord(record), failureState, failedProgress,
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
    public Optional<ExecutionRecord> findLatestByPackageId(String tenantId, String packageId) {
        return queryRepository.findLatestByPackageId(tenantId, packageId);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.SUPPORTS, readOnly = true)
    public Optional<ExecutionRecord> findByAggregateRunId(
            String tenantId,
            String packageId,
            String aggregateRunId) {
        return queryRepository.findByAggregateRunId(tenantId, packageId, aggregateRunId);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void deleteFinishedExecutionsForPackages(String tenantId, List<String> packageIds) {
        if (!StringUtils.hasText(tenantId)) {
            throw new IllegalArgumentException("tenantId is required for execution cleanup.");
        }
        String normalizedTenantId = tenantId.trim();
        Set<String> normalized = new LinkedHashSet<>();
        if (packageIds != null) {
            for (String packageId : packageIds) {
                if (StringUtils.hasText(packageId)) {
                    normalized.add(packageId.trim());
                }
            }
        }
        for (String packageId : normalized) {
            if (queryRepository.findRunningByPackageId(normalizedTenantId, packageId).isPresent()) {
                continue;
            }
            jdbcTemplate.update(
                    "delete from official_verification_execution_state_history where package_id = ? and tenant_id = ?",
                    packageId,
                    normalizedTenantId);
            jdbcTemplate.update(
                    "delete from official_verification_metric_execution_ledger where package_id = ? and tenant_id = ?",
                    packageId,
                    normalizedTenantId);
            jdbcTemplate.update(
                    "delete from official_verification_execution_lock where package_id = ? and tenant_id = ?",
                    packageId,
                    normalizedTenantId);
        }
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.SUPPORTS, readOnly = true)
    public List<OfficialVerificationMetricExecutionStatus> metricStatuses(ExecutionRecord record) {
        return queryRepository.metricStatuses(record);
    }

    private void recoverStaleExecution(String tenantId, String packageId) {
        Optional<ExecutionRecord> candidate = queryRepository.findRunningByPackageId(tenantId, packageId);
        if (candidate.isEmpty() || candidate.get().updatedAt() == null) {
            return;
        }
        ExecutionRecord stale = candidate.get();
        Instant cutoff = Instant.now().minus(staleExecutionTimeout);
        if (stale.updatedAt().isAfter(cutoff)) {
            return;
        }
        Timestamp failedAt = nowTimestamp();
        String retryInstruction = "Retry the same evidence package after confirming that the interrupted execution is no longer active.";
        String failureReason = "Official verification execution exceeded the configured stale timeout.";
        int updated = jdbcTemplate.update("""
                        update official_verification_execution_lock
                           set state = ?,
                               failed_at = ?,
                               updated_at = ?,
                               recoverable = ?,
                               retry_instruction = ?,
                               failure_reason = ?,
                               failure_stage = ?
                         where id = ?
                           and tenant_id = ?
                           and state = ?
                           and updated_at <= ?
                        """,
                STATE_FAILED_RECOVERABLE,
                failedAt,
                failedAt,
                true,
                retryInstruction,
                failureReason,
                stale.state(),
                stale.id(),
                stale.tenantId(),
                stale.state(),
                Timestamp.from(cutoff));
        if (updated != 1) {
            return;
        }
        ExecutionRecord recovered = queryRepository.queryByKey(stale.tenantId(), stale.idempotencyKey())
                .orElseThrow(() -> new IllegalStateException(
                        "Recovered official verification execution cannot be read."));
        IllegalStateException timeoutFailure = new IllegalStateException(failureReason);
        progressStore.markIncompleteMetricsFailed(
                recovered,
                recovered.aggregateRunId(),
                timeoutFailure,
                true,
                retryInstruction,
                recovered.progressPercent());
        progressStore.recordState(
                recovered,
                STATE_FAILED_RECOVERABLE,
                recovered.progressPercent(),
                "Interrupted official verification was marked recoverable after its stale timeout elapsed.",
                true,
                failureReason,
                retryInstruction);
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
