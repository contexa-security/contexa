package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialRunPackageRunLoader.LoadedRunPackage;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceCase;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceScope;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunAttemptSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunAuditSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunLedgerConsistency;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunRemediationGroup;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunSummaryCounts;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessEventSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessHistorySnapshot;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessScope;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessStepSnapshot;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

final class OfficialRunPackageDetailAssembler {

    private static final Set<String> PASS_STATES = Set.of("SUCCESS", "PASS", "PASSED");
    private static final Set<String> NOT_APPLICABLE_STATES = Set.of("NOT_APPLICABLE", "NOT_APPLICABLE_METRIC");

    private final PromptQualityAssuranceCaseService assuranceCaseService;
    private final PromptQualityProcessRunService processRunService;
    private final OfficialVerificationOperatorSnapshotService operatorSnapshotService;
    private final OfficialRunOperatorSnapshotMapper operatorSnapshotMapper;
    private final OfficialRunAttemptSummaryFactory attemptSummaryFactory;
    private final OfficialRunMetricSummaryCalculator summaryCalculator;
    private final OfficialRunLedgerConsistencyEvaluator ledgerConsistencyEvaluator;
    private final OfficialRunAuditSnapshotFactory auditSnapshotFactory;

    OfficialRunPackageDetailAssembler(
            PromptQualityAssuranceCaseService assuranceCaseService,
            PromptQualityProcessRunService processRunService,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            OfficialRunOperatorSnapshotMapper operatorSnapshotMapper,
            OfficialRunAttemptSummaryFactory attemptSummaryFactory,
            OfficialRunMetricSummaryCalculator summaryCalculator,
            OfficialRunLedgerConsistencyEvaluator ledgerConsistencyEvaluator,
            OfficialRunAuditSnapshotFactory auditSnapshotFactory) {
        this.assuranceCaseService = Objects.requireNonNull(assuranceCaseService, "assuranceCaseService");
        this.processRunService = Objects.requireNonNull(processRunService, "processRunService");
        this.operatorSnapshotService = Objects.requireNonNull(operatorSnapshotService, "operatorSnapshotService");
        this.operatorSnapshotMapper = Objects.requireNonNull(operatorSnapshotMapper, "operatorSnapshotMapper");
        this.attemptSummaryFactory = Objects.requireNonNull(attemptSummaryFactory, "attemptSummaryFactory");
        this.summaryCalculator = Objects.requireNonNull(summaryCalculator, "summaryCalculator");
        this.ledgerConsistencyEvaluator = Objects.requireNonNull(ledgerConsistencyEvaluator, "ledgerConsistencyEvaluator");
        this.auditSnapshotFactory = Objects.requireNonNull(auditSnapshotFactory, "auditSnapshotFactory");
    }

    OfficialRunPackageDetail assemble(String packageId, LoadedRunPackage loaded, int expectedMetricCount) {
        List<OfficialVerificationMetricTrace> runs = loaded.runs();
        OperatorSnapshot snapshot = loaded.operatorSnapshot();
        RuntimeEvidencePackageDetail sealedEvidence = loaded.sealedEvidence();
        List<OfficialRunFailureCause> failureCauses = failureCauses(runs, snapshot);
        CertificateData certificate = certificate(snapshot);
        PromptQualityAssuranceCase assuranceCase = assuranceCase(sealedEvidence);
        RemediationData remediation = remediation(snapshot, failureCauses);
        ProcessData process = process(sealedEvidence);
        List<OfficialRunAttemptSummary> attempts = attemptSummaryFactory.summaries(
                loaded.allPackageRuns(), loaded.aggregateRunId(), packageId, expectedMetricCount);
        List<OfficialRunAuditSnapshot> auditSnapshots = auditSnapshotFactory.snapshots(
                packageId, loaded.aggregateRunId(), runs, sealedEvidence, assuranceCase,
                failureCauses, remediation.nextActions(), process.events(), snapshot);
        List<OfficialVerificationPromptComparison> promptComparisons = promptComparisons(packageId, loaded.aggregateRunId());
        List<OfficialActualPromptProblem> actualPromptProblems = summaryCalculator.actualPromptProblems(snapshot);
        OfficialRunSummaryCounts summaryCounts = summaryCalculator.summaryCounts(runs, actualPromptProblems);
        return detail(
                packageId, loaded, failureCauses, certificate, assuranceCase, remediation, process,
                attempts, auditSnapshots, promptComparisons, actualPromptProblems, summaryCounts);
    }

    private OfficialRunPackageDetail detail(
            String packageId,
            LoadedRunPackage loaded,
            List<OfficialRunFailureCause> failureCauses,
            CertificateData certificate,
            PromptQualityAssuranceCase assuranceCase,
            RemediationData remediation,
            ProcessData process,
            List<OfficialRunAttemptSummary> attempts,
            List<OfficialRunAuditSnapshot> auditSnapshots,
            List<OfficialVerificationPromptComparison> promptComparisons,
            List<OfficialActualPromptProblem> actualPromptProblems,
            OfficialRunSummaryCounts summaryCounts) {
        List<OfficialVerificationMetricTrace> runs = loaded.runs();
        int passed = (int) runs.stream().filter(this::passed).count();
        int failed = (int) runs.stream().filter(this::failed).count();
        OfficialRunLedgerConsistency ledgerConsistency = ledgerConsistencyEvaluator.evaluate(loaded.officialResult(), runs);
        return new OfficialRunPackageDetail(
                packageId, loaded.aggregateRunId(), loaded.officialResult().integrityValid(), runs.size(), passed, failed,
                ledgerConsistency, loaded.sealedEvidence(), runs, promptComparisons, actualPromptProblems,
                failureCauses, remediation.nextActions(),
                summaryCalculator.nextActionHref(packageId, loaded.aggregateRunId(), summaryCounts),
                summaryCounts, remediation.groups(), assuranceCase == null ? null : assuranceCase.caseId(),
                certificate.id(), certificate.state(), certificate.stateLabel(), certificate.usable(), certificate.summary(),
                summaryCalculator.actualPromptProblemSummaries(actualPromptProblems), attempts,
                process.steps(), process.history(), process.events(), auditSnapshots);
    }

    private List<OfficialRunFailureCause> failureCauses(
            List<OfficialVerificationMetricTrace> runs,
            OperatorSnapshot snapshot) {
        List<OfficialRunFailureCause> runFailures = runs.stream()
                .flatMap(run -> run.failureCauses().stream())
                .toList();
        List<OfficialRunFailureCause> operatorFailures = operatorSnapshotMapper.failureCauses(snapshot);
        return operatorFailures.isEmpty() ? runFailures : operatorFailures;
    }

    private CertificateData certificate(OperatorSnapshot snapshot) {
        boolean available = snapshot != null && snapshot.available();
        String id = available ? snapshot.batch().certificateId() : null;
        String state = available ? snapshot.batch().finalDecision() : null;
        String stateLabel = StringUtils.hasText(state) ? operatorSnapshotMapper.stateLabel(state) : null;
        boolean usable = available && StringUtils.hasText(id) && !snapshot.batch().blocked();
        String summary = available ? snapshot.batch().blockReasonSummary() : null;
        return new CertificateData(id, state, stateLabel, usable, summary);
    }

    private RemediationData remediation(
            OperatorSnapshot snapshot,
            List<OfficialRunFailureCause> failures) {
        List<OfficialRunRemediationGroup> groups = operatorSnapshotMapper.remediationGroups(snapshot);
        List<String> nextActions = operatorSnapshotMapper.merge(
                operatorSnapshotMapper.groupNextActions(groups), operatorSnapshotMapper.nextActions(failures));
        return new RemediationData(groups, nextActions);
    }

    private ProcessData process(RuntimeEvidencePackageDetail sealedEvidence) {
        PromptQualityProcessScope scope = processScope(sealedEvidence);
        return new ProcessData(
                processRunService.steps(scope), processRunService.history(scope), processRunService.events(scope));
    }

    private List<OfficialVerificationPromptComparison> promptComparisons(String packageId, String aggregateRunId) {
        List<OfficialVerificationPromptComparison> stored = operatorSnapshotService.promptComparisons(packageId, aggregateRunId);
        return stored == null ? List.of() : stored;
    }

    private PromptQualityAssuranceCase assuranceCase(RuntimeEvidencePackageDetail sealedEvidence) {
        PromptQualityAssuranceScope scope = assuranceScope(sealedEvidence);
        return scope == null ? null : assuranceCaseService.findCase(scope);
    }

private PromptQualityAssuranceScope assuranceScope(RuntimeEvidencePackageDetail sealedEvidence) {
        if (sealedEvidence == null || sealedEvidence.summary() == null) {
            return null;
        }
        return new PromptQualityAssuranceScope(
                sealedEvidence.summary().tenantId(),
                sealedEvidence.summary().requestPath(),
                sealedEvidence.summary().resourceId(),
                sealedEvidence.summary().httpMethod(),
                PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION,
                PromptQualityAssuranceScope.DEFAULT_MODEL_PROFILE,
                PromptQualityAssuranceScope.DEFAULT_VERIFIER_VERSION);
    }
    private PromptQualityProcessScope processScope(RuntimeEvidencePackageDetail sealedEvidence) {
        return PromptQualityProcessScope.fromAssuranceScope(assuranceScope(sealedEvidence));
    }

    private boolean passed(OfficialVerificationMetricTrace run) {
        return run != null && PASS_STATES.contains(normalize(run.state()));
    }

    private boolean failed(OfficialVerificationMetricTrace run) {
        return run != null && failedState(run.state());
    }

    private boolean failedState(String state) {
        String normalized = normalize(state);
        return StringUtils.hasText(normalized)
                && !PASS_STATES.contains(normalized)
                && !NOT_APPLICABLE_STATES.contains(normalized);
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private record CertificateData(String id, String state, String stateLabel, boolean usable, String summary) {
    }

    private record RemediationData(List<OfficialRunRemediationGroup> groups, List<String> nextActions) {
    }

    private record ProcessData(
            List<PromptQualityProcessStepSnapshot> steps,
            List<PromptQualityProcessHistorySnapshot> history,
            List<PromptQualityProcessEventSnapshot> events) {
    }
}