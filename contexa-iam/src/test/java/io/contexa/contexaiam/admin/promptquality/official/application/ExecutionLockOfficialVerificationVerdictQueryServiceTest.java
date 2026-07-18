package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationVerdict;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationSubject;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ExecutionLockOfficialVerificationVerdictQueryServiceTest {

    @Test
    void returnsVerdictOnlyFromExactCompletedPackageAndAggregateRun() {
        OfficialVerificationExecutionLockService executionLockService = mock(OfficialVerificationExecutionLockService.class);
        OfficialVerificationExecutionLockService.ExecutionRecord record = completedRecord("sep-001", "agg-001");
        OfficialVerificationVerdict verdict = verdict("sep-001", "agg-001");
        when(executionLockService.findByAggregateRunId("tenant-a", "sep-001", "agg-001"))
                .thenReturn(Optional.of(record));
        when(executionLockService.completedResult(record)).thenReturn(Optional.of(run(verdict)));

        OfficialVerificationVerdictQueryService service =
                new ExecutionLockOfficialVerificationVerdictQueryService(executionLockService);

        assertThat(service.findPersisted("sep-001", "agg-001", subject())).contains(verdict);
        verify(executionLockService, never()).findLatestByPackageId("tenant-a", "sep-001");
    }

    @Test
    void rejectsAggregateRunMismatchBeforeReadingCompletedResult() {
        OfficialVerificationExecutionLockService executionLockService = mock(OfficialVerificationExecutionLockService.class);
        OfficialVerificationExecutionLockService.ExecutionRecord record = completedRecord("sep-001", "agg-002");
        when(executionLockService.findByAggregateRunId("tenant-a", "sep-001", "agg-001"))
                .thenReturn(Optional.empty());

        OfficialVerificationVerdictQueryService service =
                new ExecutionLockOfficialVerificationVerdictQueryService(executionLockService);

        assertThat(service.findPersisted("sep-001", "agg-001", subject())).isEmpty();
        verify(executionLockService, never()).completedResult(record);
    }

    @Test
    void rejectsVerdictWhenPersistedRunBelongsToAnotherResource() {
        OfficialVerificationExecutionLockService executionLockService = mock(OfficialVerificationExecutionLockService.class);
        OfficialVerificationExecutionLockService.ExecutionRecord record = completedRecord("sep-001", "agg-001");
        when(executionLockService.findByAggregateRunId("tenant-a", "sep-001", "agg-001"))
                .thenReturn(Optional.of(record));
        when(executionLockService.completedResult(record)).thenReturn(Optional.of(run(verdict("sep-001", "agg-001"))));

        OfficialVerificationVerdictQueryService service =
                new ExecutionLockOfficialVerificationVerdictQueryService(executionLockService);
        OfficialVerificationSubject anotherResource =
                new OfficialVerificationSubject("tenant-a", "/api/payments", "payments.read", "GET");

        assertThat(service.findPersisted("sep-001", "agg-001", anotherResource)).isEmpty();
    }

    private OfficialVerificationExecutionLockService.ExecutionRecord completedRecord(
            String packageId,
            String aggregateRunId) {
        return new OfficialVerificationExecutionLockService.ExecutionRecord(
                1L,
                "idempotency-001",
                "base-001",
                packageId,
                "tenant-a",
                aggregateRunId,
                1,
                1,
                OfficialVerificationExecutionLockService.STATE_COMPLETED,
                100,
                false,
                null,
                null,
                null,
                "operator-admin",
                null,
                "{}",
                "{}",
                Instant.EPOCH,
                Instant.EPOCH,
                null,
                Instant.EPOCH,
                Instant.EPOCH,
                false);
    }

    private RuntimeEvidenceVerificationRun run(OfficialVerificationVerdict verdict) {
        return new RuntimeEvidenceVerificationRun(
                verdict.aggregateRunId(),
                verdict.packageId(),
                "2026-07-15 00:00:00",
                null,
                "Eligible",
                12,
                12,
                0,
                "tenant-a",
                "user-a",
                "/api/orders",
                "orders.read",
                "GET",
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                "request-001",
                "prompt-hash",
                "context-hash",
                List.of(),
                List.of(),
                List.of(),
                RuntimeEvidencePromptConsistencyResult.empty(),
                OfficialVerificationExecutionLockService.STATE_COMPLETED,
                100,
                verdict);
    }

    private OfficialVerificationSubject subject() {
        return new OfficialVerificationSubject("tenant-a", "/api/orders", "orders.read", "GET");
    }

    private OfficialVerificationVerdict verdict(String packageId, String aggregateRunId) {
        return new OfficialVerificationVerdict(
                packageId,
                aggregateRunId,
                OfficialVerificationVerdict.Status.ELIGIBLE,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                "2026-07-15 00:00:00");
    }
}
