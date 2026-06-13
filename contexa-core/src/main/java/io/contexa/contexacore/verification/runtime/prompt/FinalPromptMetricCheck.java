package io.contexa.contexacore.verification.runtime.prompt;

import io.contexa.contexacore.verification.metric.OfficialMetricCheckObservation;

public record FinalPromptMetricCheck(
        String metricCode,
        String checkCode,
        String label,
        String expectedValue,
        String actualValue,
        boolean passed,
        String source,
        String severity,
        String failureType,
        String remediationOwner,
        String operatorReason,
        String nextAction,
        String reverifyCriterion,
        String issueKey,
        boolean customerVisible,
        String readinessScope,
        String purposeVersion,
        String inputReadinessState,
        String purposeResult,
        String detectedSignalsJson,
        String interpretationLinksJson,
        String decisionUtility,
        String whyItMatters
) {

    public OfficialMetricCheckObservation toOfficialObservation() {
        return new OfficialMetricCheckObservation(
                checkCode,
                label,
                expectedValue,
                actualValue,
                passed,
                source,
                severity,
                failureType,
                remediationOwner,
                operatorReason,
                nextAction,
                reverifyCriterion,
                issueKey,
                customerVisible,
                readinessScope,
                purposeVersion,
                inputReadinessState,
                purposeResult,
                detectedSignalsJson,
                interpretationLinksJson,
                decisionUtility,
                whyItMatters);
    }
}
