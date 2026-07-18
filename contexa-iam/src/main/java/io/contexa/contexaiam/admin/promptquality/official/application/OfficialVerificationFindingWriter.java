package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationFindingWriter {

    void insert(FindingCommand command);

    record FindingCommand(
            FindingIdentity identity,
            FindingClassification classification,
            FindingNarrative narrative) {
    }

    record FindingIdentity(
            String aggregateRunId,
            String officialRunId,
            String packageId,
            String certificateId,
            String caseId,
            String issueId,
            String metricCode,
            String checkCode) {
    }

    record FindingClassification(
            String severity,
            String evidencePath,
            String expectedValue,
            String actualValue,
            String relatedProcessStep,
            String comparisonFieldKey,
            String comparisonState,
            String promptLocation) {
    }

    record FindingNarrative(
            String title,
            String summary,
            String problemStatement,
            String rootCause,
            String affectedTarget,
            String operatorReason,
            String evidenceSummary,
            String expectedResult,
            String actualResult,
            String impact,
            String remediationOwner,
            String nextAction,
            String reverifyCriterion,
            String customerVisibleSeverity) {
    }
}
