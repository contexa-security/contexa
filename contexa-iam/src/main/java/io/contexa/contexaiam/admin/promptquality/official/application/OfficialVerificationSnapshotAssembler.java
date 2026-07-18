package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorAuditSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorFinding;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorPurposeEvidence;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorRemediationGroup;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorRunBatch;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;

import java.util.List;
import java.util.Map;

public final class OfficialVerificationSnapshotAssembler {

    public OperatorSnapshot assemble(
            OperatorRunBatch batch,
            List<OperatorMetricSnapshot> metrics,
            List<OperatorFinding> findings,
            List<OperatorRemediationGroup> remediationGroups,
            List<OfficialActualPromptProblem> actualPromptProblems,
            List<OperatorPurposeEvidence> purposeEvidence,
            List<OperatorAuditSnapshot> auditSnapshots) {
        return new OperatorSnapshot(
                batch,
                immutable(metrics),
                immutable(findings),
                immutable(remediationGroups),
                immutable(actualPromptProblems),
                immutable(purposeEvidence),
                immutable(auditSnapshots));
    }

    public List<OperatorSnapshot> assembleAll(
            List<OperatorRunBatch> batches,
            Map<String, List<OperatorMetricSnapshot>> metrics,
            Map<String, List<OperatorFinding>> findings,
            Map<String, List<OperatorRemediationGroup>> remediationGroups,
            Map<String, List<OfficialActualPromptProblem>> actualPromptProblems,
            Map<String, List<OperatorPurposeEvidence>> purposeEvidence,
            Map<String, List<OperatorAuditSnapshot>> auditSnapshots) {
        return immutable(batches).stream()
                .map(batch -> assemble(
                        batch,
                        rows(metrics, batch.aggregateRunId()),
                        rows(findings, batch.aggregateRunId()),
                        rows(remediationGroups, batch.aggregateRunId()),
                        rows(actualPromptProblems, batch.aggregateRunId()),
                        rows(purposeEvidence, batch.aggregateRunId()),
                        rows(auditSnapshots, batch.aggregateRunId())))
                .toList();
    }

    private <T> List<T> rows(Map<String, List<T>> rowsByAggregateRunId, String aggregateRunId) {
        if (rowsByAggregateRunId == null) {
            return List.of();
        }
        return immutable(rowsByAggregateRunId.get(aggregateRunId));
    }

    private <T> List<T> immutable(List<T> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}