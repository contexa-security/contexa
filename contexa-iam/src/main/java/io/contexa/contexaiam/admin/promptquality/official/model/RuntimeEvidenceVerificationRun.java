package io.contexa.contexaiam.admin.promptquality.official.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityIssue;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record RuntimeEvidenceVerificationRun(
        String runId,
        String packageId,
        String generatedAt,
        String caseId,
        String certificateId,
        String certificateState,
        String certificateStateLabel,
        boolean certificateIssued,
        String certificateSummary,
        String plainSummary,
        int totalMetricCount,
        int passedMetricCount,
        int failedMetricCount,
        String tenantId,
        String userId,
        String requestPath,
        String resourceId,
        String httpMethod,
        List<RuntimeEvidenceMetricResult> metrics,
        List<PromptQualityIssue> issues,
        List<String> blockingFindings,
        List<String> nextActions,
        String requestId,
        String promptHash,
        String contextHash,
        List<OfficialRunFailureCause> failureCauses,
        List<OfficialVerificationPromptComparison> promptComparisons,
        List<OfficialActualPromptProblem> actualPromptProblems,
        RuntimeEvidencePromptConsistencyResult promptConsistency,
        String executionState,
        Integer progressPercent) {

    public RuntimeEvidenceVerificationRun(
            String runId,
            String packageId,
            String generatedAt,
            String caseId,
            String certificateId,
            String certificateState,
            String certificateStateLabel,
            boolean certificateIssued,
            String certificateSummary,
            String plainSummary,
            int totalMetricCount,
            int passedMetricCount,
            int failedMetricCount,
            String tenantId,
            String userId,
            String requestPath,
            String resourceId,
            String httpMethod,
            List<RuntimeEvidenceMetricResult> metrics,
            List<PromptQualityIssue> issues,
            List<String> blockingFindings,
            List<String> nextActions,
            String requestId,
            String promptHash,
            String contextHash,
            List<OfficialRunFailureCause> failureCauses,
            List<OfficialVerificationPromptComparison> promptComparisons,
            List<OfficialActualPromptProblem> actualPromptProblems,
            RuntimeEvidencePromptConsistencyResult promptConsistency) {
        this(
                runId,
                packageId,
                generatedAt,
                caseId,
                certificateId,
                certificateState,
                certificateStateLabel,
                certificateIssued,
                certificateSummary,
                plainSummary,
                totalMetricCount,
                passedMetricCount,
                failedMetricCount,
                tenantId,
                userId,
                requestPath,
                resourceId,
                httpMethod,
                metrics,
                issues,
                blockingFindings,
                nextActions,
                requestId,
                promptHash,
                contextHash,
                failureCauses,
                promptComparisons,
                actualPromptProblems,
                promptConsistency,
                certificateState,
                null);
    }

    public RuntimeEvidenceVerificationRun(
            String runId,
            String packageId,
            String generatedAt,
            String caseId,
            String certificateId,
            String certificateState,
            String certificateStateLabel,
            boolean certificateIssued,
            String certificateSummary,
            String plainSummary,
            int totalMetricCount,
            int passedMetricCount,
            int failedMetricCount,
            String tenantId,
            String userId,
            String requestPath,
            String resourceId,
            String httpMethod,
            List<RuntimeEvidenceMetricResult> metrics,
            List<PromptQualityIssue> issues,
            List<String> blockingFindings,
            List<String> nextActions,
            String requestId,
            String promptHash,
            String contextHash,
            List<OfficialRunFailureCause> failureCauses,
            List<OfficialVerificationPromptComparison> promptComparisons,
            RuntimeEvidencePromptConsistencyResult promptConsistency,
            String executionState,
            Integer progressPercent) {
        this(
                runId,
                packageId,
                generatedAt,
                caseId,
                certificateId,
                certificateState,
                certificateStateLabel,
                certificateIssued,
                certificateSummary,
                plainSummary,
                totalMetricCount,
                passedMetricCount,
                failedMetricCount,
                tenantId,
                userId,
                requestPath,
                resourceId,
                httpMethod,
                metrics,
                issues,
                blockingFindings,
                nextActions,
                requestId,
                promptHash,
                contextHash,
                failureCauses,
                promptComparisons,
                List.of(),
                promptConsistency,
                executionState,
                progressPercent);
    }

    public RuntimeEvidenceVerificationRun(
            String runId,
            String packageId,
            String generatedAt,
            String caseId,
            String certificateId,
            String certificateState,
            String certificateStateLabel,
            boolean certificateIssued,
            String certificateSummary,
            String plainSummary,
            int totalMetricCount,
            int passedMetricCount,
            int failedMetricCount,
            String tenantId,
            String userId,
            String requestPath,
            String resourceId,
            String httpMethod,
            List<RuntimeEvidenceMetricResult> metrics,
            List<PromptQualityIssue> issues,
            List<String> blockingFindings,
            List<String> nextActions,
            String requestId,
            String promptHash,
            String contextHash,
            List<OfficialRunFailureCause> failureCauses,
            List<OfficialVerificationPromptComparison> promptComparisons,
            RuntimeEvidencePromptConsistencyResult promptConsistency) {
        this(
                runId,
                packageId,
                generatedAt,
                caseId,
                certificateId,
                certificateState,
                certificateStateLabel,
                certificateIssued,
                certificateSummary,
                plainSummary,
                totalMetricCount,
                passedMetricCount,
                failedMetricCount,
                tenantId,
                userId,
                requestPath,
                resourceId,
                httpMethod,
                metrics,
                issues,
                blockingFindings,
                nextActions,
                requestId,
                promptHash,
                contextHash,
                failureCauses,
                promptComparisons,
                List.of(),
                promptConsistency,
                certificateState,
                null);
    }

    public RuntimeEvidenceVerificationRun(
            String runId,
            String packageId,
            String generatedAt,
            String caseId,
            String certificateId,
            String certificateState,
            String certificateStateLabel,
            boolean certificateIssued,
            String certificateSummary,
            String plainSummary,
            int totalMetricCount,
            int passedMetricCount,
            int failedMetricCount,
            String tenantId,
            String userId,
            String requestPath,
            String resourceId,
            String httpMethod,
            List<RuntimeEvidenceMetricResult> metrics,
            List<PromptQualityIssue> issues,
            List<String> blockingFindings,
            List<String> nextActions,
            String requestId,
            String promptHash,
            String contextHash,
            List<OfficialRunFailureCause> failureCauses,
            List<OfficialVerificationPromptComparison> promptComparisons) {
        this(
                runId,
                packageId,
                generatedAt,
                caseId,
                certificateId,
                certificateState,
                certificateStateLabel,
                certificateIssued,
                certificateSummary,
                plainSummary,
                totalMetricCount,
                passedMetricCount,
                failedMetricCount,
                tenantId,
                userId,
                requestPath,
                resourceId,
                httpMethod,
                metrics,
                issues,
                blockingFindings,
                nextActions,
                requestId,
                promptHash,
                contextHash,
                failureCauses,
                promptComparisons,
                List.of(),
                RuntimeEvidencePromptConsistencyResult.empty());
    }

    public RuntimeEvidenceVerificationRun {
        metrics = metrics == null ? List.of() : List.copyOf(metrics);
        issues = issues == null ? List.of() : List.copyOf(issues);
        blockingFindings = blockingFindings == null ? List.of() : List.copyOf(blockingFindings);
        nextActions = nextActions == null ? List.of() : List.copyOf(nextActions);
        failureCauses = failureCauses == null ? List.of() : List.copyOf(failureCauses);
        promptComparisons = promptComparisons == null ? List.of() : List.copyOf(promptComparisons);
        actualPromptProblems = actualPromptProblems == null ? List.of() : List.copyOf(actualPromptProblems);
        promptConsistency = promptConsistency == null ? RuntimeEvidencePromptConsistencyResult.empty() : promptConsistency;
    }

    @JsonProperty("aggregateRunId")
    public String aggregateRunId() {
        return runId;
    }

    @JsonProperty("resourceUrl")
    public String resourceUrl() {
        return requestPath;
    }

    @JsonProperty("state")
    public String state() {
        return officialVerificationPassed() ? "CERTIFIABLE" : certificateState;
    }

    @JsonProperty("stateLabel")
    public String stateLabel() {
        return officialVerificationPassed() ? "공식검사 통과" : certificateStateLabel;
    }

    @JsonProperty("officialFinalDecision")
    public String officialFinalDecision() {
        return officialVerificationPassed() ? "CERTIFIABLE" : "BLOCKED";
    }

    @JsonProperty("officialVerificationPassed")
    public boolean officialVerificationPassed() {
        return totalMetricCount >= 12 && passedMetricCount >= totalMetricCount && failedMetricCount == 0;
    }
}
