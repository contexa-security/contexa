package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record RuntimeEvidenceReverifyRequest(
        String packageId,
        String operatorId,
        String reason,
        String sourcePackageId,
        String sourceAggregateRunId,
        List<String> findingIds,
        List<String> issueIds) {

    public RuntimeEvidenceReverifyRequest(String packageId, String operatorId, String reason) {
        this(packageId, operatorId, reason, null, null, List.of(), List.of());
    }

    public RuntimeEvidenceReverifyRequest {
        findingIds = findingIds == null ? List.of() : List.copyOf(findingIds);
        issueIds = issueIds == null ? List.of() : List.copyOf(issueIds);
    }
}
