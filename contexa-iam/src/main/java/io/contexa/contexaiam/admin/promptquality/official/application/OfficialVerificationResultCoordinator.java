package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationResult;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceCase;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityIssue;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationVerdict;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceGateResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Objects;

public final class OfficialVerificationResultCoordinator {

    private final PromptQualityAssuranceCaseService assuranceCaseService;
    private final RuntimeIssueDiagnosticService runtimeIssueDiagnosticService;
    private final OfficialVerificationProgressRecorder progressRecorder;
    private final OfficialVerificationResultAssembler resultAssembler;
    private final OfficialVerificationOperatorSnapshotService operatorSnapshotService;
    private final OfficialVerificationExecutionLedger executionLedger;
    private final PromptQualityMessageResolver messageResolver;
    private final OfficialVerificationVerdictFactory verdictFactory = new OfficialVerificationVerdictFactory();

    public OfficialVerificationResultCoordinator(
            PromptQualityAssuranceCaseService assuranceCaseService,
            RuntimeIssueDiagnosticService runtimeIssueDiagnosticService,
            OfficialVerificationProgressRecorder progressRecorder,
            OfficialVerificationResultAssembler resultAssembler,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            OfficialVerificationExecutionLedger executionLedger,
            PromptQualityMessageResolver messageResolver) {
        this.assuranceCaseService = Objects.requireNonNull(assuranceCaseService, "assuranceCaseService");
        this.runtimeIssueDiagnosticService = Objects.requireNonNull(
                runtimeIssueDiagnosticService, "runtimeIssueDiagnosticService");
        this.progressRecorder = Objects.requireNonNull(progressRecorder, "progressRecorder");
        this.resultAssembler = Objects.requireNonNull(resultAssembler, "resultAssembler");
        this.operatorSnapshotService = Objects.requireNonNull(operatorSnapshotService, "operatorSnapshotService");
        this.executionLedger = Objects.requireNonNull(executionLedger, "executionLedger");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    public RuntimeEvidenceVerificationRun completeEligible(
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            OfficialVerificationExecutionLockService.ExecutionRecord executionRecord,
            OfficialSealedEvidenceVerificationResult officialResult,
            RuntimeEvidenceGateResult policyResult,
            String promptGovernanceVersion,
            String metricSetVersion,
            String engineVersion) {
        EligibleInitial initial = assembleEligibleInitial(evidence, officialResult, policyResult);
        EligibleFinal finalized = finalizeEligibleEvidence(evidence, initial);
        recordEligibleProgress(
                evidence,
                initial,
                finalized,
                promptGovernanceVersion,
                metricSetVersion,
                engineVersion);
        RuntimeEvidenceVerificationRun run = eligibleRun(evidence, initial, finalized);
        executionLedger.markCompleted(executionRecord, initial.runId(), run);
        return run;
    }

    public RuntimeEvidenceVerificationRun completeIneligible(
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            OfficialVerificationExecutionLockService.ExecutionRecord executionRecord,
            String aggregateRunId,
            RuntimeEvidenceGateResult policyResult) {
        OfficialVerificationVerdict verdict = verdictFactory.create(
                evidence.evidencePackage().getPackageId(),
                aggregateRunId,
                evidence.generatedAt(),
                policyResult,
                evidence.promptConsistency());
        if (verdict.eligible()) {
            throw new IllegalStateException("The pre-metric completion path requires an ineligible verdict.");
        }
        IneligibleArtifacts artifacts = ineligibleArtifacts(evidence, aggregateRunId, verdict);
        recordIneligibleEvidence(evidence, executionRecord, aggregateRunId, verdict, artifacts);
        RuntimeEvidenceVerificationRun run = ineligibleRun(evidence, aggregateRunId, verdict, artifacts);
        executionLedger.markCompleted(executionRecord, aggregateRunId, run);
        return run;
    }

    private EligibleInitial assembleEligibleInitial(
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            OfficialSealedEvidenceVerificationResult officialResult,
            RuntimeEvidenceGateResult policyResult) {
        List<? extends OfficialVerificationRunView> runs = officialResult.runs();
        List<OfficialVerificationPromptComparison> comparisons =
                resultAssembler.promptComparisons(evidence.evidencePackage(), runs);
        List<RuntimeEvidenceMetricResult> metrics = resultAssembler.metrics(
                runs, comparisons, evidence.evidencePackage().getPackageId());
        String runId = officialResult.aggregateRunId();
        OfficialVerificationVerdict verdict = verdictFactory.create(
                evidence.evidencePackage().getPackageId(),
                runId,
                evidence.generatedAt(),
                policyResult,
                evidence.promptConsistency());
        PromptQualityAssuranceCase assuranceCase = assuranceCaseService.recordVerification(
                evidence.assuranceScope(),
                runId,
                verdict.failures().size(),
                message(
                        "enterprise.pqa.runtimeVerification.case.summaryTpl",
                        evidence.evidencePackage().getPackageId()));
        List<String> rawNextActions = verdict.eligible()
                ? List.of(message("enterprise.pqa.runtimeVerification.next.eligible"))
                : verdict.nextActions();
        List<String> nextActions = resultAssembler.customerSentences(rawNextActions, false);
        List<PromptQualityIssue> issues = runtimeIssueDiagnosticService.recordIssues(
                runId,
                evidence.evidencePackage().getPackageId(),
                evidence.httpMethod(),
                resultAssembler.issueMetrics(metrics, evidence.promptConsistency()),
                nextActions);
        return new EligibleInitial(
                runId, verdict, assuranceCase, issues, metrics, comparisons,
                resultAssembler.failureCauses(metrics), evidence.requestId(), evidence.promptHash(), evidence.contextHash());
    }

    private EligibleFinal finalizeEligibleEvidence(
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            EligibleInitial initial) {
        operatorSnapshotService.record(
                initial.runId(),
                evidence.evidencePackage(),
                evidence.requestPath(),
                evidence.actualResourceId(),
                evidence.httpMethod(),
                initial.promptHash(),
                initial.contextHash(),
                null,
                initial.assuranceCase() == null ? null : initial.assuranceCase().caseId(),
                initial.issues(),
                initial.metrics(),
                initial.promptComparisons());
        List<OfficialVerificationPromptComparison> storedComparisons =
                operatorSnapshotService.promptComparisons(
                        evidence.evidencePackage().getPackageId(), initial.runId());
        List<OfficialVerificationPromptComparison> comparisons = storedComparisons.isEmpty()
                ? initial.promptComparisons()
                : storedComparisons;
        List<OfficialActualPromptProblem> problems = operatorSnapshotService.actualPromptProblems(
                evidence.evidencePackage().getPackageId(), initial.runId());
        List<String> findings = resultAssembler.findings(initial.verdict().findings(), problems);
        List<String> nextActions = resultAssembler.nextActions(initial.verdict().nextActions(), problems);
        if (nextActions.isEmpty() && initial.verdict().eligible()) {
            nextActions = List.of(message("enterprise.pqa.runtimeVerification.next.eligible"));
        }
        return new EligibleFinal(
                comparisons,
                problems,
                findings,
                nextActions,
                resultAssembler.passedMetricCount(initial.metrics()),
                resultAssembler.failedMetricCount(initial.metrics()));
    }

    private void recordEligibleProgress(
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            EligibleInitial initial,
            EligibleFinal finalized,
            String promptGovernanceVersion,
            String metricSetVersion,
            String engineVersion) {
        progressRecorder.recordCompletion(
                evidence.processScope(),
                initial.verdict(),
                evidence.evidencePackage(),
                initial.runId(),
                finalized.failedMetricCount(),
                finalized.nextActions());
        List<String> failedMetricCodes = initial.metrics().stream()
                .filter(OfficialVerificationMetricClassifier::customerBlocking)
                .map(RuntimeEvidenceMetricResult::metricCode)
                .toList();
        progressRecorder.recordAuditSnapshot(new OfficialVerificationProgressRecorder.AuditSnapshotCommand(
                evidence.processScope(),
                initial.verdict(),
                initial.assuranceCase(),
                evidence.evidencePackage(),
                initial.runId(),
                initial.metrics(),
                finalized.failedMetricCount(),
                failedMetricCodes,
                finalized.findings(),
                finalized.nextActions(),
                initial.requestId(),
                initial.promptHash(),
                initial.contextHash(),
                promptGovernanceVersion,
                metricSetVersion,
                engineVersion,
                evidence.operatorId()));
    }

    private RuntimeEvidenceVerificationRun eligibleRun(
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            EligibleInitial initial,
            EligibleFinal finalized) {
        return new RuntimeEvidenceVerificationRun(
                initial.runId(),
                evidence.evidencePackage().getPackageId(),
                evidence.generatedAt(),
                initial.assuranceCase() == null ? null : initial.assuranceCase().caseId(),
                initial.verdict().eligible()
                        ? message("enterprise.pqa.runtimeVerification.process.eligibleSummary")
                        : message("enterprise.pqa.runtimeVerification.process.ineligibleSummary"),
                initial.metrics().size(),
                finalized.passedMetricCount(),
                finalized.failedMetricCount(),
                evidence.evidencePackage().getTenantId(),
                evidence.evidencePackage().getUserId(),
                evidence.requestPath(),
                evidence.resourceId(),
                evidence.httpMethod(),
                initial.metrics(),
                initial.issues(),
                finalized.findings(),
                finalized.nextActions(),
                initial.requestId(),
                initial.promptHash(),
                initial.contextHash(),
                initial.failureCauses(),
                finalized.promptComparisons(),
                finalized.actualPromptProblems(),
                evidence.promptConsistency(),
                OfficialVerificationExecutionLockService.STATE_COMPLETED,
                100,
                initial.verdict());
    }

    private IneligibleArtifacts ineligibleArtifacts(
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            String aggregateRunId,
            OfficialVerificationVerdict verdict) {
        List<String> findings = verdict.findings().isEmpty()
                ? verdict.failures().stream()
                .map(failure -> firstNonBlank(
                        failure.message(), failure.checkCode(), failure.messageKey()))
                .toList()
                : verdict.findings();
        List<String> nextActions = verdict.nextActions().isEmpty()
                ? verdict.failures().stream()
                .map(failure -> firstNonBlank(
                        failure.nextAction(), message("enterprise.pqa.runtimeVerification.result.resolveFailedGate")))
                .distinct()
                .toList()
                : verdict.nextActions();
        PromptQualityAssuranceCase assuranceCase = assuranceCaseService.recordVerification(
                evidence.assuranceScope(),
                aggregateRunId,
                verdict.failures().size(),
                message("enterprise.pqa.runtimeVerification.result.ineligibleCaseSummary"));
        List<PromptQualityIssue> issues = runtimeIssueDiagnosticService.recordIssues(
                aggregateRunId,
                evidence.evidencePackage().getPackageId(),
                evidence.httpMethod(),
                List.of(),
                nextActions);
        return new IneligibleArtifacts(
                findings, nextActions, assuranceCase, issues,
                evidence.requestId(), evidence.promptHash(), evidence.contextHash());
    }

    private void recordIneligibleEvidence(
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            OfficialVerificationExecutionLockService.ExecutionRecord executionRecord,
            String aggregateRunId,
            OfficialVerificationVerdict verdict,
            IneligibleArtifacts artifacts) {
        operatorSnapshotService.record(
                aggregateRunId,
                evidence.evidencePackage(),
                evidence.requestPath(),
                evidence.actualResourceId(),
                evidence.httpMethod(),
                artifacts.promptHash(),
                artifacts.contextHash(),
                null,
                artifacts.assuranceCase() == null ? null : artifacts.assuranceCase().caseId(),
                artifacts.issues(),
                List.of(),
                List.of());
        executionLedger.transitionMessage(
                executionRecord,
                OfficialVerificationExecutionLockService.STATE_SNAPSHOT_WRITING,
                OfficialVerificationProgressPolicy.SNAPSHOT_WRITING,
                "enterprise.pqa.runtimeVerification.progress.ineligibleSnapshotWriting");
        progressRecorder.recordIneligibleBeforeMetrics(
                evidence.processScope(),
                evidence.evidencePackage(),
                aggregateRunId,
                verdict,
                artifacts.nextActions(),
                evidence.operatorId());
    }

    private RuntimeEvidenceVerificationRun ineligibleRun(
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            String aggregateRunId,
            OfficialVerificationVerdict verdict,
            IneligibleArtifacts artifacts) {
        return new RuntimeEvidenceVerificationRun(
                aggregateRunId,
                evidence.evidencePackage().getPackageId(),
                evidence.generatedAt(),
                artifacts.assuranceCase() == null ? null : artifacts.assuranceCase().caseId(),
                message("enterprise.pqa.runtimeVerification.process.ineligibleSummary"),
                0, 0, 0,
                evidence.evidencePackage().getTenantId(),
                evidence.evidencePackage().getUserId(),
                evidence.requestPath(),
                evidence.resourceId(),
                evidence.httpMethod(),
                List.of(),
                artifacts.issues(),
                artifacts.findings(),
                artifacts.nextActions(),
                artifacts.requestId(),
                artifacts.promptHash(),
                artifacts.contextHash(),
                List.of(), List.of(), List.of(),
                evidence.promptConsistency(),
                OfficialVerificationExecutionLockService.STATE_COMPLETED,
                100,
                verdict);
    }

    private String firstNonBlank(String... values) {
        if (values != null) {
            for (String value : values) {
                if (StringUtils.hasText(value)) {
                    return value.trim();
                }
            }
        }
        return "";
    }

    private String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }

    private record EligibleInitial(
            String runId,
            OfficialVerificationVerdict verdict,
            PromptQualityAssuranceCase assuranceCase,
            List<PromptQualityIssue> issues,
            List<RuntimeEvidenceMetricResult> metrics,
            List<OfficialVerificationPromptComparison> promptComparisons,
            List<OfficialRunFailureCause> failureCauses,
            String requestId,
            String promptHash,
            String contextHash) {
    }

    private record EligibleFinal(
            List<OfficialVerificationPromptComparison> promptComparisons,
            List<OfficialActualPromptProblem> actualPromptProblems,
            List<String> findings,
            List<String> nextActions,
            int passedMetricCount,
            int failedMetricCount) {
    }

    private record IneligibleArtifacts(
            List<String> findings,
            List<String> nextActions,
            PromptQualityAssuranceCase assuranceCase,
            List<PromptQualityIssue> issues,
            String requestId,
            String promptHash,
            String contextHash) {
    }
}