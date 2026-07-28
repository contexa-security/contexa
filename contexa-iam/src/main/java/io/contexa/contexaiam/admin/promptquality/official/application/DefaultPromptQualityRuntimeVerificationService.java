package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.Objects;


import io.contexa.contexacore.verification.adjudication.ScorecardResult;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.replay.DeterministicReplayResult;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRequest;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationResult;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRuntime;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationExecutionStatus;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceGateResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import io.contexa.contexaiam.admin.promptquality.official.application.ProtectableResourceDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public class DefaultPromptQualityRuntimeVerificationService
        implements PromptQualityRuntimeVerificationService {

    private static final Logger log = LoggerFactory.getLogger(DefaultPromptQualityRuntimeVerificationService.class);

    private final OfficialSealedEvidenceVerificationRuntime officialSealedEvidenceVerificationRuntime;
    private final OfficialVerificationEvidencePreflight evidencePreflight;
    private final PromptQualityRuntimeCertificationPolicy certificationPolicy;
    private final OfficialVerificationMetricContract metricContract;
    private final OfficialVerificationProgressRecorder progressRecorder;
    private final OfficialVerificationExecutionLedger executionLedger;
    private final OfficialVerificationResultCoordinator resultCoordinator;
    private final OfficialVerificationReverificationCoordinator reverificationCoordinator;

    public DefaultPromptQualityRuntimeVerificationService(
            OfficialSealedEvidenceVerificationRuntime officialSealedEvidenceVerificationRuntime,
            OfficialVerificationEvidencePreflight evidencePreflight,
            PromptQualityRuntimeCertificationPolicy certificationPolicy,
            OfficialVerificationMetricContract metricContract,
            OfficialVerificationProgressRecorder progressRecorder,
            OfficialVerificationExecutionLedger executionLedger,
            OfficialVerificationResultCoordinator resultCoordinator,
            OfficialVerificationReverificationCoordinator reverificationCoordinator) {
        this.officialSealedEvidenceVerificationRuntime = Objects.requireNonNull(
                officialSealedEvidenceVerificationRuntime, "officialSealedEvidenceVerificationRuntime");
        this.evidencePreflight = Objects.requireNonNull(evidencePreflight, "evidencePreflight");
        this.certificationPolicy = Objects.requireNonNull(certificationPolicy, "certificationPolicy");
        this.metricContract = Objects.requireNonNull(metricContract, "metricContract");
        this.progressRecorder = Objects.requireNonNull(progressRecorder, "progressRecorder");
        this.executionLedger = Objects.requireNonNull(executionLedger, "executionLedger");
        this.resultCoordinator = Objects.requireNonNull(resultCoordinator, "resultCoordinator");
        this.reverificationCoordinator = Objects.requireNonNull(reverificationCoordinator, "reverificationCoordinator");
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public RuntimeEvidenceVerificationRun verify(RuntimeEvidenceVerificationRequest request) {
        OfficialVerificationEvidencePreflight.EvidenceContext evidence = evidencePreflight.load(request);
        OfficialVerificationExecutionLockService.ExecutionRecord executionRecord = null;
        try {
            ProtectableResourceDescriptor descriptor = evidencePreflight.resolveDescriptor(evidence);
            executionRecord = executionLedger.start(request, evidence, descriptor);
            return executeVerification(evidence, executionRecord);
        }
        catch (RuntimeException ex) {
            recordFailure(request, evidence, executionRecord, ex);
            throw ex;
        }
    }

    private RuntimeEvidenceVerificationRun executeVerification(
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            OfficialVerificationExecutionLockService.ExecutionRecord executionRecord) {
        SealedEvidencePackage evidencePackage = evidence.evidencePackage();
        progressRecorder.completePrerequisites(
                evidence.processScope(), evidencePackage, evidence.integrityValid(),
                evidence.promptConsistency(), evidence.operatorId());
        if (!executionRecord.acquired()) {
            return executionLedger.idempotentRun(executionRecord, evidence);
        }
        prepareExecution(evidence, executionRecord);
        ScorecardResult scorecard = evidencePreflight.scorecard(evidencePackage);
        DeterministicReplayResult replay = evidencePreflight.replay(evidencePackage);
        String aggregateRunId = executionLedger.failureAggregateRunId(evidencePackage, executionRecord);
        RuntimeEvidenceGateResult preliminaryResult = certificationPolicy.evaluate(
                evidencePackage, evidence.integrityValid(), scorecard, replay, List.of());
        RuntimeEvidenceGateResult preMetricResult = metricContract.withoutMetricExecutionChecks(preliminaryResult);
        RuntimeEvidencePromptConsistencyResult consistency = evidence.promptConsistency();
        if (consistency == null || consistency.blocking()) {
            return resultCoordinator.completeIneligible(evidence, executionRecord, aggregateRunId, preMetricResult);
        }
        return executeMetrics(evidence, executionRecord, scorecard, replay, aggregateRunId);
    }

    private void prepareExecution(
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            OfficialVerificationExecutionLockService.ExecutionRecord executionRecord) {
        executionLedger.replacePreviousDiagnostics(evidence);
        executionLedger.transitionMessage(
                executionRecord,
                OfficialVerificationExecutionLockService.STATE_EVIDENCE_LOADED,
                OfficialVerificationProgressPolicy.EVIDENCE_LOADED,
                "enterprise.pqa.runtimeVerification.progress.evidenceLoaded");
        progressRecorder.assertProcessReady(evidence.processScope());
        executionLedger.transitionMessage(
                executionRecord,
                OfficialVerificationExecutionLockService.STATE_CONSISTENCY_CHECKED,
                OfficialVerificationProgressPolicy.CONSISTENCY_CHECKED,
                "enterprise.pqa.runtimeVerification.progress.consistencyChecked");
        progressRecorder.start(evidence.processScope(), evidence.evidencePackage(), evidence.operatorId());
    }

    private RuntimeEvidenceVerificationRun executeMetrics(
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            OfficialVerificationExecutionLockService.ExecutionRecord executionRecord,
            ScorecardResult scorecard,
            DeterministicReplayResult replay,
            String aggregateRunId) {
        SealedEvidencePackage evidencePackage = evidence.evidencePackage();
        executionLedger.transitionMessage(
                executionRecord,
                OfficialVerificationExecutionLockService.STATE_PREFLIGHT_FINAL_PROMPT_CONTRACT,
                OfficialVerificationProgressPolicy.FINAL_PROMPT_PREFLIGHT,
                "enterprise.pqa.runtimeVerification.progress.preflightChecking");
        evidencePreflight.assertFinalPromptReady(evidencePackage);
        executionLedger.markMetricsRunning(executionRecord, aggregateRunId);
        OfficialSealedEvidenceVerificationResult officialResult = officialSealedEvidenceVerificationRuntime.executeAll(
                new OfficialSealedEvidenceVerificationRequest(evidencePackage.getPackageId(), evidence.operatorId()));
        List<? extends OfficialVerificationRunView> runViews = officialResult.runs();
        metricContract.assertComplete(runViews);
        progressRecorder.recordMetricFinished(executionRecord, officialResult.aggregateRunId(), runViews);
        executionLedger.transitionMessage(
                executionRecord,
                OfficialVerificationExecutionLockService.STATE_SNAPSHOT_WRITING,
                OfficialVerificationProgressPolicy.SNAPSHOT_WRITING,
                "enterprise.pqa.runtimeVerification.progress.snapshotWriting");
        RuntimeEvidenceGateResult policyResult = certificationPolicy.evaluate(
                evidencePackage, evidence.integrityValid(), scorecard, replay, runViews);
        return resultCoordinator.completeEligible(
                evidence,
                executionRecord,
                officialResult,
                policyResult,
                evidencePreflight.promptGovernanceVersion(evidence.promptMetadata()),
                metricContract.metricSetVersion(),
                metricContract.engineVersion());
    }

    private void recordFailure(
            RuntimeEvidenceVerificationRequest request,
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            OfficialVerificationExecutionLockService.ExecutionRecord executionRecord,
            RuntimeException failure) {
        SealedEvidencePackage evidencePackage = evidence.evidencePackage();
        log.error(
                "PQA official verification failed. packageId={}, requestPath={}, resourceId={}, httpMethod={}, executionRecordPresent={}, executionState={}",
                evidencePackage.getPackageId(), evidence.requestPath(), evidence.resourceId(), evidence.httpMethod(),
                executionRecord != null, executionRecord == null ? null : executionRecord.state(), failure);
        OfficialVerificationExecutionLockService.ExecutionRecord failureRecord = executionRecord == null
                ? executionLedger.startFailureRecord(request, evidence)
                : executionRecord;
        recordLedgerFailure(evidence, failureRecord, failure);
        recordProcessFailure(evidence, failure);
    }

    private void recordLedgerFailure(
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            OfficialVerificationExecutionLockService.ExecutionRecord executionRecord,
            RuntimeException failure) {
        try {
            executionLedger.markFailed(executionRecord, failure);
        }
        catch (RuntimeException ledgerFailure) {
            log.error(
                    "PQA official verification failure ledger write failed. packageId={}, requestPath={}, resourceId={}, httpMethod={}, executionRecordPresent={}",
                    evidence.evidencePackage().getPackageId(), evidence.requestPath(), evidence.resourceId(),
                    evidence.httpMethod(), executionRecord != null, ledgerFailure);
        }
    }

    private void recordProcessFailure(
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            RuntimeException failure) {
        try {
            progressRecorder.recordFailure(
                    evidence.processScope(), evidence.evidencePackage(), evidence.operatorId(), failure);
        }
        catch (RuntimeException processFailure) {
            log.error(
                    "PQA official verification process failure write failed. packageId={}, requestPath={}, resourceId={}, httpMethod={}",
                    evidence.evidencePackage().getPackageId(), evidence.requestPath(), evidence.resourceId(),
                    evidence.httpMethod(), processFailure);
        }
    }
    @Override
    public OfficialVerificationExecutionStatus executionStatus(String packageId) {
        return executionLedger.status(packageId);
    }
    @Override
    public OfficialVerificationExecutionStatus executionStatus(String packageId, String aggregateRunId) {
        return executionLedger.status(packageId, aggregateRunId);
    }
    @Override
    public RuntimeEvidenceReverifyResult reverify(RuntimeEvidenceReverifyRequest request) {
        RuntimeEvidenceVerificationRun run = verify(reverificationCoordinator.verificationRequest(request));
        return reverificationCoordinator.complete(request, run);
    }
}
