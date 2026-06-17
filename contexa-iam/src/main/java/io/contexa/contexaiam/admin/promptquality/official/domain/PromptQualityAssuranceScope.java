package io.contexa.contexaiam.admin.promptquality.official.domain;

public record PromptQualityAssuranceScope(
        String tenantId,
        String resourceUrl,
        String resourceId,
        String httpMethod,
        String promptContractVersion,
        String modelProfile,
        String verifierVersion) {

    public static final String DEFAULT_TENANT_ID = "default";
    public static final String DEFAULT_HTTP_METHOD = "GET";
    public static final String DEFAULT_PROMPT_CONTRACT_VERSION = "official-prompt-contract-v1";
    public static final String DEFAULT_MODEL_PROFILE = "default-model-profile";
    public static final String DEFAULT_VERIFIER_VERSION = "official-verifier-v1";

    public static PromptQualityAssuranceScope fromBundle(ContextEvidenceBundle bundle) {
        return new PromptQualityAssuranceScope(
                bundle == null ? null : bundle.tenantId(),
                bundle == null ? null : bundle.resourceUrl(),
                bundle == null ? null : bundle.resourceId(),
                bundle == null ? null : bundle.httpMethod(),
                DEFAULT_PROMPT_CONTRACT_VERSION,
                DEFAULT_MODEL_PROFILE,
                DEFAULT_VERIFIER_VERSION
        );
    }

    public static PromptQualityAssuranceScope fromResource(ProtectableResourceView resource) {
        return new PromptQualityAssuranceScope(
                resource == null ? null : resource.tenantId(),
                resource == null ? null : resource.resourceUrl(),
                resource == null ? null : resource.resourceId(),
                resource == null ? null : resource.httpMethod(),
                resource == null ? null : resource.promptContractVersion(),
                resource == null ? null : resource.modelProfile(),
                resource == null ? null : resource.verifierVersion()
        );
    }

    public static PromptQualityAssuranceScope fromCertificate(PromptQualityCertificateView certificate) {
        return new PromptQualityAssuranceScope(
                certificate == null ? null : certificate.tenantId(),
                certificate == null ? null : certificate.resourceUrl(),
                certificate == null ? null : certificate.resourceId(),
                certificate == null ? null : certificate.httpMethod(),
                certificate == null ? null : certificate.promptContractVersion(),
                certificate == null ? null : certificate.modelProfile(),
                certificate == null ? null : certificate.verifierVersion()
        );
    }
}
