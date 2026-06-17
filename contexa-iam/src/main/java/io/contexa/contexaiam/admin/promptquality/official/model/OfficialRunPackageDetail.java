package io.contexa.contexaiam.admin.promptquality.official.model;

import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessEventSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessHistorySnapshot;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessStepSnapshot;

import java.util.List;

public record OfficialRunPackageDetail(
        String packageId,
        String aggregateRunId,
        boolean integrityValid,
        int totalRunCount,
        int passedRunCount,
        int failedRunCount,
        OfficialRunLedgerConsistency ledgerConsistency,
        RuntimeEvidencePackageDetail sealedEvidence,
        List<OfficialVerificationMetricTrace> runs,
        List<OfficialVerificationPromptComparison> promptComparisons,
        List<OfficialActualPromptProblem> actualPromptProblems,
        List<OfficialRunFailureCause> failureCauses,
        List<String> nextActions,
        String nextActionHref,
        OfficialRunSummaryCounts summaryCounts,
        List<OfficialRunRemediationGroup> remediationGroups,
        String caseId,
        String certificateId,
        String certificateState,
        String certificateStateLabel,
        boolean certificateIssued,
        String certificateSummary,
        List<String> blockingFindings,
        List<OfficialRunAttemptSummary> attempts,
        List<PromptQualityProcessStepSnapshot> processSteps,
        List<PromptQualityProcessHistorySnapshot> processHistory,
        List<PromptQualityProcessEventSnapshot> processEvents,
        List<OfficialRunAuditSnapshot> auditSnapshots) {

    public OfficialRunPackageDetail(
            String packageId,
            String aggregateRunId,
            boolean integrityValid,
            int totalRunCount,
            int passedRunCount,
            int failedRunCount,
            OfficialRunLedgerConsistency ledgerConsistency,
            RuntimeEvidencePackageDetail sealedEvidence,
            List<OfficialVerificationMetricTrace> runs,
            List<OfficialVerificationPromptComparison> promptComparisons,
            List<OfficialRunFailureCause> failureCauses,
            List<String> nextActions) {
        this(
                packageId,
                aggregateRunId,
                integrityValid,
                totalRunCount,
                passedRunCount,
                failedRunCount,
                ledgerConsistency,
                sealedEvidence,
                runs,
                promptComparisons,
                List.of(),
                failureCauses,
                nextActions,
                null,
                OfficialRunSummaryCounts.empty(),
                List.of(),
                null,
                null,
                null,
                null,
                false,
                null,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of());
    }

    public OfficialRunPackageDetail(
            String packageId,
            String aggregateRunId,
            boolean integrityValid,
            int totalRunCount,
            int passedRunCount,
            int failedRunCount,
            OfficialRunLedgerConsistency ledgerConsistency,
            RuntimeEvidencePackageDetail sealedEvidence,
            List<OfficialVerificationMetricTrace> runs,
            List<OfficialVerificationPromptComparison> promptComparisons,
            List<OfficialRunFailureCause> failureCauses,
            List<String> nextActions,
            String caseId,
            String certificateId,
            String certificateState,
            String certificateStateLabel,
            boolean certificateIssued,
            String certificateSummary,
            List<String> blockingFindings,
            List<OfficialRunAttemptSummary> attempts,
            List<PromptQualityProcessStepSnapshot> processSteps,
            List<PromptQualityProcessHistorySnapshot> processHistory,
            List<PromptQualityProcessEventSnapshot> processEvents,
            List<OfficialRunAuditSnapshot> auditSnapshots) {
        this(
                packageId,
                aggregateRunId,
                integrityValid,
                totalRunCount,
                passedRunCount,
                failedRunCount,
                ledgerConsistency,
                sealedEvidence,
                runs,
                promptComparisons,
                List.of(),
                failureCauses,
                nextActions,
                null,
                OfficialRunSummaryCounts.empty(),
                List.of(),
                caseId,
                certificateId,
                certificateState,
                certificateStateLabel,
                certificateIssued,
                certificateSummary,
                blockingFindings,
                attempts,
                processSteps,
                processHistory,
                processEvents,
                auditSnapshots);
    }

    public OfficialRunPackageDetail {
        runs = runs == null ? List.of() : List.copyOf(runs);
        promptComparisons = promptComparisons == null ? List.of() : List.copyOf(promptComparisons);
        actualPromptProblems = actualPromptProblems == null ? List.of() : List.copyOf(actualPromptProblems);
        failureCauses = failureCauses == null ? List.of() : List.copyOf(failureCauses);
        nextActions = nextActions == null ? List.of() : List.copyOf(nextActions);
        nextActionHref = nextActionHref == null ? null : nextActionHref;
        summaryCounts = summaryCounts == null ? OfficialRunSummaryCounts.empty() : summaryCounts;
        remediationGroups = remediationGroups == null ? List.of() : List.copyOf(remediationGroups);
        blockingFindings = blockingFindings == null ? List.of() : List.copyOf(blockingFindings);
        attempts = attempts == null ? List.of() : List.copyOf(attempts);
        processSteps = processSteps == null ? List.of() : List.copyOf(processSteps);
        processHistory = processHistory == null ? List.of() : List.copyOf(processHistory);
        processEvents = processEvents == null ? List.of() : List.copyOf(processEvents);
        auditSnapshots = auditSnapshots == null ? List.of() : List.copyOf(auditSnapshots);
    }
}
