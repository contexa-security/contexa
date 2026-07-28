package io.contexa.contexaiam.admin.promptquality.official.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckState;

import java.util.List;
import java.util.Map;

public record OfficialVerificationMetricTrace(
        String metricCode,
        String metricName,
        String groupName,
        String metricPurpose,
        String metricQualityQuestion,
        String officialRunId,
        String requestId,
        String requestPath,
        String state,
        String stateLabel,
        double score,
        int passedChecks,
        int totalChecks,
        Long processingTimeMs,
        String startedAt,
        String completedAt,
        List<OfficialRunCheckDetail> checks,
        Map<String, String> requestFacts,
        Map<String, String> eventFacts,
        Map<String, String> promptFacts,
        Map<String, String> analysisFacts,
        List<OfficialRunEventDetail> events,
        Map<String, Object> rawEvidence,
        List<OfficialVerificationPromptComparison> comparisons,
        List<OfficialActualPromptProblem> actualPromptProblems,
        List<OfficialRunFailureCause> failureCauses,
        List<OfficialMetricPurposeEvidence> purposeEvidence,
        String operatorTitle,
        String operatorSummary,
        String primaryFailureReason,
        String remediationOwner,
        String nextAction,
        String reverifyCriterion) {

    public OfficialVerificationMetricTrace(
            String metricCode,
            String metricName,
            String groupName,
            String officialRunId,
            String requestId,
            String requestPath,
            String state,
            String stateLabel,
            double score,
            int passedChecks,
            int totalChecks,
            Long processingTimeMs,
            String startedAt,
            String completedAt,
            List<OfficialRunCheckDetail> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<OfficialRunEventDetail> events,
            Map<String, Object> rawEvidence,
            List<OfficialVerificationPromptComparison> comparisons,
            List<OfficialRunFailureCause> failureCauses) {
        this(
                metricCode,
                metricName,
                groupName,
                "",
                "",
                officialRunId,
                requestId,
                requestPath,
                state,
                stateLabel,
                score,
                passedChecks,
                totalChecks,
                processingTimeMs,
                startedAt,
                completedAt,
                checks,
                requestFacts,
                eventFacts,
                promptFacts,
                analysisFacts,
                events,
                rawEvidence,
                comparisons,
                List.of(),
                failureCauses,
                List.of(),
                "",
                "",
                "",
                "",
                "",
                "");
    }

    public OfficialVerificationMetricTrace(
            String metricCode,
            String metricName,
            String groupName,
            String officialRunId,
            String requestId,
            String requestPath,
            String state,
            String stateLabel,
            double score,
            int passedChecks,
            int totalChecks,
            Long processingTimeMs,
            String startedAt,
            String completedAt,
            List<OfficialRunCheckDetail> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<OfficialRunEventDetail> events,
            Map<String, Object> rawEvidence,
            List<OfficialVerificationPromptComparison> comparisons,
            List<OfficialActualPromptProblem> actualPromptProblems,
            List<OfficialRunFailureCause> failureCauses) {
        this(
                metricCode,
                metricName,
                groupName,
                "",
                "",
                officialRunId,
                requestId,
                requestPath,
                state,
                stateLabel,
                score,
                passedChecks,
                totalChecks,
                processingTimeMs,
                startedAt,
                completedAt,
                checks,
                requestFacts,
                eventFacts,
                promptFacts,
                analysisFacts,
                events,
                rawEvidence,
                comparisons,
                actualPromptProblems,
                failureCauses,
                List.of(),
                "",
                "",
                "",
                "",
                "",
                "");
    }

    @JsonProperty("resourceUrl")
    public String resourceUrl() {
        return requestPath;
    }

    @JsonProperty("failedChecks")
    public int failedChecks() {
        return checkCount(OfficialVerificationCheckState.FAIL);
    }

    @JsonProperty("notApplicableChecks")
    public int notApplicableChecks() {
        return checkCount(OfficialVerificationCheckState.NOT_APPLICABLE);
    }

    @JsonProperty("notEvaluatedChecks")
    public int notEvaluatedChecks() {
        return checkCount(OfficialVerificationCheckState.NOT_EVALUATED);
    }

    private int checkCount(OfficialVerificationCheckState state) {
        return checks == null ? 0 : (int) checks.stream()
                .filter(check -> check != null && check.evaluationState() == state)
                .count();
    }
}
