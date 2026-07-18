package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationMetricPurposeWriter {

    void insertReadiness(ReadinessCommand command);

    void insertPurpose(PurposeCommand command);

    void insertCustomerDisplay(CustomerDisplayCommand command);

    record ReadinessCommand(
            String packageId,
            String aggregateRunId,
            String metricCode,
            String checkCode,
            String contractVersion,
            String readinessState,
            String detectedInputsJson,
            String missingInputsJson,
            String readinessScope,
            boolean customerVisible) {
    }

    record PurposeCommand(
            String packageId,
            String aggregateRunId,
            String metricCode,
            String checkCode,
            String contractVersion,
            String purposeStatement,
            String decisionUtility,
            String purposeResult,
            String issueKey,
            boolean customerVisible,
            String readinessScope,
            String detectedSignalsJson,
            String interpretationLinksJson,
            String expectedValue,
            String actualValue,
            String remediationOwner,
            String nextAction,
            String reverifyCriterion) {
    }

    record CustomerDisplayCommand(
            String packageId,
            String aggregateRunId,
            String metricCode,
            String checkCode,
            String contractVersion,
            String displayRole,
            String title,
            String summary,
            String evidenceText,
            String whyItMatters,
            String resolutionAction,
            String reverifyCondition,
            String contextItemsJson,
            String boundFactsJson,
            String rawEvidenceRef) {
    }
}
