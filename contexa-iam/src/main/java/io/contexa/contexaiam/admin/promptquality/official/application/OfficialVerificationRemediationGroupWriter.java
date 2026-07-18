package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationRemediationGroupWriter {

    void insert(RemediationGroupCommand command);

    record RemediationGroupCommand(
            GroupIdentity identity,
            GroupClassification classification,
            GroupNarrative narrative) {
    }

    record GroupIdentity(
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId) {
    }

    record GroupClassification(
            String rootCauseKey,
            String affectedMetricCodes,
            String affectedCheckCodes,
            int findingCount,
            String relatedProcessStep,
            String comparisonFieldKeys,
            String promptLocations) {
    }

    record GroupNarrative(
            String remediationOwner,
            String title,
            String reason,
            String nextAction,
            String reverifyCriterion) {
    }
}
