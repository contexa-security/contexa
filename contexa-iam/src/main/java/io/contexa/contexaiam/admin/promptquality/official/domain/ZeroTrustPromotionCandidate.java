package io.contexa.contexaiam.admin.promptquality.official.domain;

import java.util.List;

public record ZeroTrustPromotionCandidate(
        String tenantId,
        String resourceId,
        String resourceUrl,
        String httpMethod,
        String operationalState,
        String operationalStateLabel,
        String certificateId,
        String certificateState,
        String certificateStateLabel,
        String evidenceSourceType,
        String sealedEvidencePackageId,
        String runtimePromptHash,
        int officialRunCount,
        int failedMetricCount,
        boolean reverifyRequired,
        String issuedAt,
        String expiresAt,
        boolean promotable,
        String decision,
        String reason,
        String nextAction,
        List<String> allowedActions) {
}
