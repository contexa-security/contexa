package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationExecutionStatus;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricExecutionStatus;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface OfficialVerificationExecutionLockService {

    String STATE_REQUESTED = "REQUESTED";
    String STATE_LOCK_ACQUIRED = "LOCK_ACQUIRED";
    String STATE_EVIDENCE_LOADED = "EVIDENCE_LOADED";
    String STATE_CONSISTENCY_CHECKED = "CONSISTENCY_CHECKED";
    String STATE_PREFLIGHT_FINAL_PROMPT_CONTRACT = "PREFLIGHT_FINAL_PROMPT_CONTRACT";
    String STATE_OFFICIAL_VERIFICATION_PREFLIGHT_FAILED = "OFFICIAL_VERIFICATION_PREFLIGHT_FAILED";
    String STATE_METRICS_RUNNING = "METRICS_RUNNING";
    String STATE_METRIC_FAILED = "METRIC_FAILED";
    String STATE_SNAPSHOT_WRITING = "SNAPSHOT_WRITING";
    String STATE_RUNNING = STATE_METRICS_RUNNING;
    String STATE_COMPLETED = "COMPLETED";
    String STATE_FAILED_RECOVERABLE = "FAILED_RECOVERABLE";
    String STATE_FAILED_TERMINAL = "FAILED_TERMINAL";
    String STATE_FAILED = STATE_FAILED_RECOVERABLE;

    ExecutionRecord start(ExecutionRequest request);

    void transition(ExecutionRecord record, String state, int progressPercent, String message);

    void markMetricsRunning(ExecutionRecord record, String aggregateRunId, List<String> metricCodes);

    void markMetricCompleted(ExecutionRecord record, String aggregateRunId, String metricCode, int progressPercent);

    void markMetricFailed(
            ExecutionRecord record,
            String aggregateRunId,
            String metricCode,
            Throwable failure,
            boolean recoverable,
            String retryInstruction);

    void markCompleted(ExecutionRecord record, String aggregateRunId, RuntimeEvidenceVerificationRun result);

    void markFailed(ExecutionRecord record, Throwable failure, boolean recoverable, String retryInstruction);

    Optional<RuntimeEvidenceVerificationRun> completedResult(ExecutionRecord record);

    Optional<ExecutionRecord> findLatestByPackageId(String tenantId, String packageId);

    Optional<ExecutionRecord> findByAggregateRunId(String tenantId, String packageId, String aggregateRunId);

    default void deleteFinishedExecutionsForPackages(String tenantId, List<String> packageIds) {
    }

    default OfficialVerificationExecutionStatus status(String tenantId, String packageId) {
        return findLatestByPackageId(tenantId, packageId)
                .map(this::status)
                .orElseGet(() -> OfficialVerificationExecutionStatus.empty(packageId));
    }

    default OfficialVerificationExecutionStatus status(
            String tenantId,
            String packageId,
            String aggregateRunId) {
        return findByAggregateRunId(tenantId, packageId, aggregateRunId)
                .map(this::status)
                .orElseGet(() -> OfficialVerificationExecutionStatus.empty(packageId));
    }

    private OfficialVerificationExecutionStatus status(ExecutionRecord record) {
        return new OfficialVerificationExecutionStatus(
                record.packageId(),
                record.aggregateRunId(),
                record.state(),
                record.progressPercent(),
                STATE_COMPLETED.equals(record.state()),
                record.failed(),
                record.recoverable(),
                record.failureReason(),
                record.retryInstruction(),
                record.revisionNo(),
                record.attemptNo(),
                record.failureStage(),
                metricStatuses(record));
    }

    default List<OfficialVerificationMetricExecutionStatus> metricStatuses(ExecutionRecord record) {
        return List.of();
    }

    record ExecutionRequest(
            String idempotencyKey,
            String baseIdempotencyKey,
            String packageId,
            String tenantId,
            String requestedBy,
            boolean forceReverification,
            String reverificationReason,
            String requestFingerprintJson) {
    }

    record ExecutionRecord(
            long id,
            String idempotencyKey,
            String baseIdempotencyKey,
            String packageId,
            String tenantId,
            String aggregateRunId,
            int revisionNo,
            int attemptNo,
            String state,
            int progressPercent,
            Boolean recoverable,
            String retryInstruction,
            String failureReason,
            String failureStage,
            String requestedBy,
            String reverificationReason,
            String requestFingerprintJson,
            String resultJson,
            Instant startedAt,
            Instant completedAt,
            Instant failedAt,
            Instant createdAt,
            Instant updatedAt,
            boolean acquired) {

        public boolean running() {
            return STATE_LOCK_ACQUIRED.equals(state)
                    || STATE_EVIDENCE_LOADED.equals(state)
                    || STATE_CONSISTENCY_CHECKED.equals(state)
                    || STATE_PREFLIGHT_FINAL_PROMPT_CONTRACT.equals(state)
                    || STATE_METRICS_RUNNING.equals(state)
                    || STATE_METRIC_FAILED.equals(state)
                    || STATE_SNAPSHOT_WRITING.equals(state)
                    || STATE_RUNNING.equals(state);
        }

        public boolean completed() {
            return STATE_COMPLETED.equals(state);
        }

        public boolean failed() {
            return STATE_FAILED_RECOVERABLE.equals(state)
                    || STATE_FAILED_TERMINAL.equals(state)
                    || STATE_OFFICIAL_VERIFICATION_PREFLIGHT_FAILED.equals(state)
                    || STATE_FAILED.equals(state);
        }

        public boolean recoverableFailure() {
            return STATE_FAILED_RECOVERABLE.equals(state) && Boolean.TRUE.equals(recoverable);
        }
    }
}
