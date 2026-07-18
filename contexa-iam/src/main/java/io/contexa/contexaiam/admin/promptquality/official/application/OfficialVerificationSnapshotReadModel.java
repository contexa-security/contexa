package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorAuditSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorFinding;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorPurposeEvidence;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorRemediationGroup;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorReverificationResult;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;

import java.util.List;
import java.util.Objects;

public final class OfficialVerificationSnapshotReadModel {

    private final OfficialVerificationMetricSnapshotRepository metricRepository;
    private final OfficialVerificationFindingRepository findingRepository;
    private final OfficialVerificationRemediationGroupRepository remediationRepository;
    private final OfficialVerificationPromptComparisonRepository comparisonRepository;
    private final OfficialVerificationActualPromptProblemRepository problemRepository;
    private final OfficialVerificationPurposeEvidenceRepository purposeRepository;
    private final OfficialVerificationAuditSnapshotRepository auditRepository;
    private final OfficialVerificationReverificationResultRepository reverificationRepository;

    public OfficialVerificationSnapshotReadModel(
            OfficialVerificationMetricSnapshotRepository metricRepository,
            OfficialVerificationFindingRepository findingRepository,
            OfficialVerificationRemediationGroupRepository remediationRepository,
            OfficialVerificationPromptComparisonRepository comparisonRepository,
            OfficialVerificationActualPromptProblemRepository problemRepository,
            OfficialVerificationPurposeEvidenceRepository purposeRepository,
            OfficialVerificationAuditSnapshotRepository auditRepository,
            OfficialVerificationReverificationResultRepository reverificationRepository) {
        this.metricRepository = Objects.requireNonNull(metricRepository, "metricRepository");
        this.findingRepository = Objects.requireNonNull(findingRepository, "findingRepository");
        this.remediationRepository = Objects.requireNonNull(remediationRepository, "remediationRepository");
        this.comparisonRepository = Objects.requireNonNull(comparisonRepository, "comparisonRepository");
        this.problemRepository = Objects.requireNonNull(problemRepository, "problemRepository");
        this.purposeRepository = Objects.requireNonNull(purposeRepository, "purposeRepository");
        this.auditRepository = Objects.requireNonNull(auditRepository, "auditRepository");
        this.reverificationRepository = Objects.requireNonNull(reverificationRepository, "reverificationRepository");
    }

    public List<OperatorMetricSnapshot> metrics(String aggregateRunId) {
        return metricRepository.findByAggregateRunId(aggregateRunId);
    }

    public List<OperatorMetricSnapshot> metrics(List<String> aggregateRunIds) {
        return metricRepository.findByAggregateRunIds(aggregateRunIds);
    }

    public List<OperatorFinding> findings(String aggregateRunId) {
        return findingRepository.findByAggregateRunId(aggregateRunId);
    }

    public List<OperatorFinding> findings(List<String> aggregateRunIds) {
        return findingRepository.findByAggregateRunIds(aggregateRunIds);
    }

    public List<OperatorRemediationGroup> remediationGroups(String aggregateRunId) {
        return remediationRepository.findByAggregateRunId(aggregateRunId);
    }

    public List<OperatorRemediationGroup> remediationGroups(List<String> aggregateRunIds) {
        return remediationRepository.findByAggregateRunIds(aggregateRunIds);
    }

    public List<OfficialVerificationPromptComparison> promptComparisons(String packageId, String aggregateRunId) {
        return comparisonRepository.findByPackageAndAggregateRunId(packageId, aggregateRunId);
    }

    public List<OfficialActualPromptProblem> actualPromptProblems(String aggregateRunId) {
        return problemRepository.findByAggregateRunId(aggregateRunId);
    }

    public List<OfficialActualPromptProblem> actualPromptProblems(List<String> aggregateRunIds) {
        return problemRepository.findByAggregateRunIds(aggregateRunIds);
    }

    public List<OperatorPurposeEvidence> purposeEvidence(String aggregateRunId) {
        return purposeRepository.findByAggregateRunId(aggregateRunId);
    }

    public List<OperatorPurposeEvidence> purposeEvidence(List<String> aggregateRunIds) {
        return purposeRepository.findByAggregateRunIds(aggregateRunIds);
    }

    public List<OperatorAuditSnapshot> auditSnapshots(String aggregateRunId) {
        return auditRepository.findByAggregateRunId(aggregateRunId);
    }

    public List<OperatorAuditSnapshot> auditSnapshots(List<String> aggregateRunIds) {
        return auditRepository.findByAggregateRunIds(aggregateRunIds);
    }

    public List<OperatorReverificationResult> reverificationResults(String packageId, String aggregateRunId) {
        return reverificationRepository.findBySource(packageId, aggregateRunId);
    }
}
