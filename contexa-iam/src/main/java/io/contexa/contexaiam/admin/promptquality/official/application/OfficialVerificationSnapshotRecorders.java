package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.Objects;

record OfficialVerificationSnapshotRecorders(
        OfficialActualPromptProblemCollector actualPromptProblems,
        OfficialMetricPurposeLedgerRecorder metricPurpose,
        OfficialVerificationMetricOutputRecorder metricOutput,
        OfficialVerificationRemediationGroupRecorder remediationGroup,
        OfficialVerificationPromptComparisonRecorder promptComparison,
        OfficialPromptSignalLedgerRecorder promptSignal,
        OfficialPromptLineageRecorder promptLineage,
        OfficialPromptFieldStateLedgerRecorder promptFieldState) {

    OfficialVerificationSnapshotRecorders {
        Objects.requireNonNull(actualPromptProblems, "actualPromptProblems");
        Objects.requireNonNull(metricPurpose, "metricPurpose");
        Objects.requireNonNull(metricOutput, "metricOutput");
        Objects.requireNonNull(remediationGroup, "remediationGroup");
        Objects.requireNonNull(promptComparison, "promptComparison");
        Objects.requireNonNull(promptSignal, "promptSignal");
        Objects.requireNonNull(promptLineage, "promptLineage");
        Objects.requireNonNull(promptFieldState, "promptFieldState");
    }
}
