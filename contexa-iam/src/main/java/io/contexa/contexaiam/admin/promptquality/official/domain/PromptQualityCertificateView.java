package io.contexa.contexaiam.admin.promptquality.official.domain;

import java.util.List;

public record PromptQualityCertificateView(
        String certificateId,
        String resourceUrl,
        String resourceId,
        String httpMethod,
        String tenantId,
        String promptContractVersion,
        String modelProfile,
        String verifierVersion,
        String state,
        String stateLabel,
        boolean usableForLlmZeroTrust,
        String zeroTrustState,
        String operationalState,
        String issuedAt,
        String expiresAt,
        String promptHash,
        String contextHash,
        int totalMetricCount,
        int verifiedMetricCount,
        int failedMetricCount,
        int missingMetricCount,
        String plainScope,
        String plainMeaning,
        List<String> limitations,
        List<String> evidenceRequestIds,
        List<String> recommendedActions,
        String sealedEvidencePackageId,
        String evidenceSourceType,
        String runtimePromptHash,
        String runtimeSystemPromptHash,
        String runtimeUserPromptHash,
        String runtimeDecisionHash,
        List<String> officialRunIds,
        boolean reverifyRequired) {

    public static final String SOURCE_SEALED_RUNTIME_PACKAGE = "SEALED_RUNTIME_PACKAGE";
    public static final String SOURCE_UNKNOWN = "UNKNOWN";
}
