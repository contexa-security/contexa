package io.contexa.contexaiam.admin.promptquality.official.process;

import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceScope;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityCertificateView;
import io.contexa.contexaiam.admin.promptquality.official.domain.ProtectableResourceView;
import io.contexa.contexaiam.admin.promptquality.official.domain.ZeroTrustPromotionCandidate;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageSummary;
import org.springframework.util.StringUtils;

import java.util.Locale;

public record PromptQualityProcessScope(
        String tenantId,
        String resourceUrl,
        String resourceId,
        String httpMethod,
        String promptContractVersion,
        String modelProfile,
        String verifierVersion) {

    public static PromptQualityProcessScope fromResource(ProtectableResourceView resource) {
        return new PromptQualityProcessScope(
                value(resource == null ? null : resource.tenantId(), PromptQualityAssuranceScope.DEFAULT_TENANT_ID),
                value(resource == null ? null : resource.resourceUrl(), ""),
                value(resource == null ? null : resource.resourceId(), ""),
                method(resource == null ? null : resource.httpMethod()),
                value(resource == null ? null : resource.promptContractVersion(), PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION),
                value(resource == null ? null : resource.modelProfile(), PromptQualityAssuranceScope.DEFAULT_MODEL_PROFILE),
                value(resource == null ? null : resource.verifierVersion(), PromptQualityAssuranceScope.DEFAULT_VERIFIER_VERSION));
    }

    public static PromptQualityProcessScope fromAssuranceScope(PromptQualityAssuranceScope scope) {
        return new PromptQualityProcessScope(
                value(scope == null ? null : scope.tenantId(), PromptQualityAssuranceScope.DEFAULT_TENANT_ID),
                value(scope == null ? null : scope.resourceUrl(), ""),
                value(scope == null ? null : scope.resourceId(), ""),
                method(scope == null ? null : scope.httpMethod()),
                value(scope == null ? null : scope.promptContractVersion(), PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION),
                value(scope == null ? null : scope.modelProfile(), PromptQualityAssuranceScope.DEFAULT_MODEL_PROFILE),
                value(scope == null ? null : scope.verifierVersion(), PromptQualityAssuranceScope.DEFAULT_VERIFIER_VERSION));
    }

    public static PromptQualityProcessScope fromCertificate(PromptQualityCertificateView certificate) {
        return new PromptQualityProcessScope(
                value(certificate == null ? null : certificate.tenantId(), PromptQualityAssuranceScope.DEFAULT_TENANT_ID),
                value(certificate == null ? null : certificate.resourceUrl(), ""),
                value(certificate == null ? null : certificate.resourceId(), ""),
                method(certificate == null ? null : certificate.httpMethod()),
                value(certificate == null ? null : certificate.promptContractVersion(), PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION),
                value(certificate == null ? null : certificate.modelProfile(), PromptQualityAssuranceScope.DEFAULT_MODEL_PROFILE),
                value(certificate == null ? null : certificate.verifierVersion(), PromptQualityAssuranceScope.DEFAULT_VERIFIER_VERSION));
    }

    public static PromptQualityProcessScope fromRuntimeEvidence(RuntimeEvidencePackageSummary summary) {
        return new PromptQualityProcessScope(
                value(summary == null ? null : summary.tenantId(), PromptQualityAssuranceScope.DEFAULT_TENANT_ID),
                value(summary == null ? null : summary.resourceUrl(), ""),
                value(summary == null ? null : summary.resourceId(), ""),
                method(summary == null ? null : summary.httpMethod()),
                PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION,
                PromptQualityAssuranceScope.DEFAULT_MODEL_PROFILE,
                PromptQualityAssuranceScope.DEFAULT_VERIFIER_VERSION);
    }

    public static PromptQualityProcessScope fromPromotionCandidate(ZeroTrustPromotionCandidate candidate) {
        return new PromptQualityProcessScope(
                value(candidate == null ? null : candidate.tenantId(), PromptQualityAssuranceScope.DEFAULT_TENANT_ID),
                value(candidate == null ? null : candidate.resourceUrl(), ""),
                value(candidate == null ? null : candidate.resourceId(), ""),
                method(candidate == null ? null : candidate.httpMethod()),
                PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION,
                PromptQualityAssuranceScope.DEFAULT_MODEL_PROFILE,
                PromptQualityAssuranceScope.DEFAULT_VERIFIER_VERSION);
    }

    public String businessKey() {
        return String.join("|",
                value(tenantId, PromptQualityAssuranceScope.DEFAULT_TENANT_ID),
                method(httpMethod),
                value(resourceId, ""),
                value(promptContractVersion, PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION),
                value(modelProfile, PromptQualityAssuranceScope.DEFAULT_MODEL_PROFILE));
    }

    private static String value(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    private static String method(String value) {
        return value(value, PromptQualityAssuranceScope.DEFAULT_HTTP_METHOD).toUpperCase(Locale.ROOT);
    }
}
