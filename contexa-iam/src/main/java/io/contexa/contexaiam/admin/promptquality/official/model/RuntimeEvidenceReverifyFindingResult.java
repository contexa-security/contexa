package io.contexa.contexaiam.admin.promptquality.official.model;

public record RuntimeEvidenceReverifyFindingResult(
        String sourcePackageId,
        String sourceAggregateRunId,
        String fixedPackageId,
        String fixedAggregateRunId,
        String findingId,
        String issueId,
        String metricCode,
        String checkCode,
        boolean resolved,
        String resolutionState,
        String reverifyCriterion,
        String sourceOperatorReason,
        String sourceActualValue,
        String fixedActualValue,
        String operatorSummary) {
}
