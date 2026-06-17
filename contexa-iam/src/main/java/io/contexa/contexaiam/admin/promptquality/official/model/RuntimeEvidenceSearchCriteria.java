package io.contexa.contexaiam.admin.promptquality.official.model;

import java.time.Instant;

public record RuntimeEvidenceSearchCriteria(
        String packageId,
        String tenantId,
        String userId,
        String resourceUrl,
        String resourceId,
        String httpMethod,
        Instant from,
        Instant to,
        int page,
        int size) {
}
