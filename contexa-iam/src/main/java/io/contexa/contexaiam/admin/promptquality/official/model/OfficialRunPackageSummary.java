package io.contexa.contexaiam.admin.promptquality.official.model;

import java.time.Instant;
import java.util.List;

public record OfficialRunPackageSummary(
        String packageId,
        String aggregateRunId,
        String finalDecision,
        boolean blocked,
        String blockReasonSummary,
        int expectedMetricCount,
        int actualMetricCount,
        int passedMetricCount,
        int failedMetricCount,
        String certificateId,
        String caseId,
        String certificateState,
        String certificateStateLabel,
        boolean certificateIssued,
        String certificateSummary,
        String promptHash,
        String contextHash,
        String contextHashState,
        String resourceTemplateId,
        String actualResourceId,
        String resourceUrlTemplate,
        String actualRequestPath,
        String httpMethod,
        Instant createdAt,
        List<OfficialRunMetricSummary> metrics,
        List<OfficialRunFailureCause> failureCauses,
        List<String> nextActions,
        String nextActionHref,
        List<OfficialRunRemediationGroup> remediationGroups,
        List<OfficialRunAttemptSummary> attempts) {

    public OfficialRunPackageSummary {
        metrics = metrics == null ? List.of() : List.copyOf(metrics);
        failureCauses = failureCauses == null ? List.of() : List.copyOf(failureCauses);
        nextActions = nextActions == null ? List.of() : List.copyOf(nextActions);
        nextActionHref = nextActionHref == null ? null : nextActionHref;
        remediationGroups = remediationGroups == null ? List.of() : List.copyOf(remediationGroups);
        attempts = attempts == null ? List.of() : List.copyOf(attempts);
    }

    public static OfficialRunPackageSummary fromDetail(OfficialRunPackageDetail detail) {
        if (detail == null) {
            return null;
        }
        List<OfficialRunMetricSummary> metricSummaries = detail.runs().stream()
                .map(run -> new OfficialRunMetricSummary(
                        run.metricCode(),
                        run.metricName(),
                        run.groupName(),
                        run.score(),
                        run.state(),
                        null,
                        run.passedChecks(),
                        run.totalChecks(),
                        Math.max(run.totalChecks() - run.passedChecks(), 0),
                        run.metricName(),
                        run.stateLabel(),
                        run.failureCauses().stream()
                                .map(OfficialRunFailureCause::problemStatement)
                                .findFirst()
                                .orElse(null),
                        run.failureCauses().stream()
                                .map(OfficialRunFailureCause::remediationOwner)
                                .findFirst()
                                .orElse(null),
                        run.failureCauses().stream()
                                .map(OfficialRunFailureCause::remediationHint)
                                .findFirst()
                                .orElse(null),
                        run.failureCauses().stream()
                                .map(OfficialRunFailureCause::reverifyCriterion)
                                .findFirst()
                                .orElse(null),
                        run.officialRunId(),
                        null))
                .toList();
        RuntimeEvidencePackageSummary evidenceSummary = detail.sealedEvidence() == null
                ? null
                : detail.sealedEvidence().summary();
        return new OfficialRunPackageSummary(
                detail.packageId(),
                detail.aggregateRunId(),
                detail.certificateIssued() ? "CERTIFICATE_ISSUED" : detail.failedRunCount() > 0 ? "BLOCKED" : "REVIEW_REQUIRED",
                !detail.certificateIssued(),
                detail.certificateSummary(),
                detail.totalRunCount(),
                detail.totalRunCount(),
                detail.passedRunCount(),
                detail.failedRunCount(),
                detail.certificateId(),
                detail.caseId(),
                detail.certificateState(),
                detail.certificateStateLabel(),
                detail.certificateIssued(),
                detail.certificateSummary(),
                evidenceSummary == null ? null : evidenceSummary.promptHash(),
                null,
                null,
                evidenceSummary == null ? null : evidenceSummary.resourceId(),
                evidenceSummary == null ? null : evidenceSummary.resourceId(),
                evidenceSummary == null ? null : evidenceSummary.requestPath(),
                evidenceSummary == null ? null : evidenceSummary.requestPath(),
                evidenceSummary == null ? null : evidenceSummary.httpMethod(),
                null,
                metricSummaries,
                detail.failureCauses(),
                detail.nextActions(),
                detail.nextActionHref(),
                detail.remediationGroups(),
                detail.attempts());
    }
}
