package io.contexa.contexaiam.admin.promptquality.official.domain;

public record PromptQualityAssuranceCase(
        String caseId,
        String caseKey,
        String tenantId,
        String resourceUrl,
        String resourceId,
        String httpMethod,
        String promptContractVersion,
        String modelProfile,
        String verifierVersion,
        String currentStage,
        String dirtyState,
        String latestBundleId,
        String latestRunId,
        String latestCertificateId,
        int latestIssueCount,
        String summary,
        String createdAt,
        String updatedAt) {
}
