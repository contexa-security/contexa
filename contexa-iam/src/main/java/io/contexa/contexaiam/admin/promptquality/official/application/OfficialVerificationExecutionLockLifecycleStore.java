package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationExecutionLockService.ExecutionRecord;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationExecutionLockService.ExecutionRequest;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;

import static io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationExecutionLockService.*;

final class OfficialVerificationExecutionLockLifecycleStore {

    private static final int REQUESTED_PROGRESS = OfficialVerificationProgressPolicy.REQUEST_ACCEPTED;
    private static final int LOCK_PROGRESS = OfficialVerificationProgressPolicy.LOCK_ACQUIRED;
    private final JdbcTemplate jdbcTemplate;
    private final OfficialVerificationExecutionLockQueryRepository queryRepository;
    private final OfficialVerificationExecutionProgressStore progressStore;

    OfficialVerificationExecutionLockLifecycleStore(
            JdbcTemplate jdbcTemplate,
            OfficialVerificationExecutionLockQueryRepository queryRepository,
            OfficialVerificationExecutionProgressStore progressStore
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.queryRepository = queryRepository;
        this.progressStore = progressStore;
    }
    ExecutionRecord startForcedRevision(ExecutionRequest request) {
        for (int attempt = 0; attempt < 3; attempt++) {
            int revision = nextRevision(request.tenantId(), request.baseIdempotencyKey());
            String revisionKey = request.baseIdempotencyKey() + ":rev:" + revision;
            boolean inserted = insertExecutionLock(request, revisionKey, revision);
            if (inserted) {
                return queryRepository.queryByKey(request.tenantId(), revisionKey)
                        .map(record -> {
                            progressStore.recordState(record, STATE_REQUESTED, REQUESTED_PROGRESS, "Forced official reverification request was accepted.", null, null, null);
                            progressStore.recordState(record, STATE_LOCK_ACQUIRED, LOCK_PROGRESS, "Forced official reverification execution lock was acquired.", null, null, null);
                            return queryRepository.acquired(record, true);
                        })
                        .orElseThrow(() -> new IllegalStateException("Forced official verification revision was inserted but cannot be read."));
            }
        }
        throw new IllegalStateException("Forced official verification revision could not acquire a unique execution lock.");
    }

    private int nextRevision(String tenantId, String baseIdempotencyKey) {
        Integer next = jdbcTemplate.queryForObject("""
                        select coalesce(max(revision_no), 0) + 1
                          from official_verification_execution_lock
                         where tenant_id = ?
                           and base_idempotency_key = ?
                        """,
                Integer.class,
                trim(tenantId),
                trim(baseIdempotencyKey));
        return next == null || next < 2 ? 2 : next;
    }

    ExecutionRecord restartFinishedOrReplay(ExecutionRecord record) {
        if (record == null || record.running()) {
            return queryRepository.acquired(record, false);
        }
        if (!record.completed() && !record.failed()) {
            return queryRepository.acquired(record, false);
        }
        jdbcTemplate.update(
                "delete from official_verification_execution_state_history where execution_lock_id = ? and tenant_id = ?",
                record.id(),
                record.tenantId());
        jdbcTemplate.update(
                "delete from official_verification_metric_execution_ledger where execution_lock_id = ? and tenant_id = ?",
                record.id(),
                record.tenantId());
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
                           and tenant_id = ?
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
                record.id(),
                record.tenantId());
        if (updated != 1) {
            return queryRepository.queryByKey(record.tenantId(), record.idempotencyKey())
                    .map(existing -> queryRepository.acquired(existing, false))
                    .orElseGet(() -> queryRepository.acquired(record, false));
        }
        ExecutionRecord retry = queryRepository.queryByKey(record.tenantId(), record.idempotencyKey())
                .orElse(record);
        progressStore.recordState(retry, STATE_REQUESTED, REQUESTED_PROGRESS,
                "Previous official verification diagnostic data was replaced by a new run for the same quality target.",
                null,
                null,
                null);
        progressStore.recordState(retry, STATE_LOCK_ACQUIRED, LOCK_PROGRESS,
                "Official verification execution lock was reacquired for the latest diagnostic run.",
                null,
                null,
                null);
        return queryRepository.acquired(retry, true);
    }

    boolean insertExecutionLock(ExecutionRequest request, String idempotencyKey, int revision) {
        String sql = """
                        insert into official_verification_execution_lock (
                            idempotency_key, base_idempotency_key, package_id, tenant_id, revision_no,
                            attempt_no, state, progress_percent, requested_by, reverification_reason,
                            request_fingerprint_json, started_at, created_at, updated_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """ + postgresqlConflictClause("idempotency_key");
        try {
            int inserted = jdbcTemplate.update(
                    sql,
                    trim(idempotencyKey),
                    trim(request.baseIdempotencyKey()),
                    trim(request.packageId()),
                    trim(request.tenantId()),
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

    private Timestamp nowTimestamp() {
        return Timestamp.from(Instant.now());
    }

    private String postgresqlConflictClause(String columnExpression) {
        return " on conflict (" + columnExpression + ") do nothing";
    }

    private String trim(String value) {
        return value == null ? null : value.trim();
    }

    private String fit(String value, int maxLength) {
        String normalized = trim(value);
        if (normalized == null || normalized.length() <= maxLength) {
            return normalized;
        }
        return normalized.substring(0, maxLength);
    }
}