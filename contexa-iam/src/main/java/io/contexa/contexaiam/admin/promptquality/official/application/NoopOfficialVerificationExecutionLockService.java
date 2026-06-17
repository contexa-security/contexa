package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public final class NoopOfficialVerificationExecutionLockService implements OfficialVerificationExecutionLockService {

    @Override
    public ExecutionRecord start(ExecutionRequest request) {
        String key = request == null ? "noop" : request.idempotencyKey();
        String baseKey = request == null ? key : request.baseIdempotencyKey();
        String packageId = request == null ? "" : request.packageId();
        return new ExecutionRecord(
                -1L,
                key,
                baseKey,
                packageId,
                null,
                1,
                1,
                STATE_LOCK_ACQUIRED,
                10,
                null,
                null,
                null,
                null,
                request == null ? null : request.requestedBy(),
                request == null ? null : request.reverificationReason(),
                request == null ? null : request.requestFingerprintJson(),
                null,
                Instant.now(),
                null,
                null,
                Instant.now(),
                Instant.now(),
                true);
    }

    @Override
    public void transition(ExecutionRecord record, String state, int progressPercent, String message) {
    }

    @Override
    public void markMetricsRunning(ExecutionRecord record, String aggregateRunId, List<String> metricCodes) {
    }

    @Override
    public void markMetricCompleted(ExecutionRecord record, String aggregateRunId, String metricCode, int progressPercent) {
    }

    @Override
    public void markMetricFailed(
            ExecutionRecord record,
            String aggregateRunId,
            String metricCode,
            Throwable failure,
            boolean recoverable,
            String retryInstruction) {
    }

    @Override
    public void markCompleted(ExecutionRecord record, String aggregateRunId, RuntimeEvidenceVerificationRun result) {
    }

    @Override
    public void markFailed(ExecutionRecord record, Throwable failure, boolean recoverable, String retryInstruction) {
    }

    @Override
    public Optional<RuntimeEvidenceVerificationRun> completedResult(ExecutionRecord record) {
        return Optional.empty();
    }

    @Override
    public Optional<ExecutionRecord> findLatestByPackageId(String packageId) {
        return Optional.empty();
    }
}
