package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.Objects;

import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationVerdict;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationSubject;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;

import java.util.Optional;

public class ExecutionLockOfficialVerificationVerdictQueryService implements OfficialVerificationVerdictQueryService {

    private final OfficialVerificationExecutionLockService executionLockService;

    public ExecutionLockOfficialVerificationVerdictQueryService(
            OfficialVerificationExecutionLockService executionLockService) {
        this.executionLockService = Objects.requireNonNull(executionLockService, "executionLockService");
    }

    @Override
    public Optional<OfficialVerificationVerdict> findPersisted(
            String packageId,
            String aggregateRunId,
            OfficialVerificationSubject subject) {
        String normalizedPackageId = value(packageId);
        String normalizedAggregateRunId = value(aggregateRunId);
        if (normalizedPackageId.isEmpty() || normalizedAggregateRunId.isEmpty() || subject == null) {
            return Optional.empty();
        }
        return executionLockService.findByAggregateRunId(
                        subject.tenantId(), normalizedPackageId, normalizedAggregateRunId)
                .filter(OfficialVerificationExecutionLockService.ExecutionRecord::completed)
                .flatMap(executionLockService::completedResult)
                .filter(subject::matches)
                .map(RuntimeEvidenceVerificationRun::verdict)
                .filter(Objects::nonNull)
                .filter(verdict -> normalizedPackageId.equals(verdict.packageId()))
                .filter(verdict -> normalizedAggregateRunId.equals(verdict.aggregateRunId()));
    }

    private static String value(String value) {
        return value == null ? "" : value.trim();
    }
}
