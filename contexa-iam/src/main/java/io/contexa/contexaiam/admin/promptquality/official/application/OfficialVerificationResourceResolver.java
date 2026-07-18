package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Objects;

public final class OfficialVerificationResourceResolver {

    private final PromptQualityProtectableResourceLookup resourceLookup;

    public OfficialVerificationResourceResolver(PromptQualityProtectableResourceLookup resourceLookup) {
        this.resourceLookup = Objects.requireNonNull(resourceLookup, "resourceLookup");
    }

    public ProtectableResourceDescriptor resolve(
            SealedEvidencePackage evidencePackage,
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            String requestPath,
            String resourceId,
            String httpMethod) {
        return resourceLookup.findBestMatch(requestPath, resourceId, httpMethod)
                .orElseGet(() -> sealedEvidenceDescriptor(
                        evidencePackage,
                        requestFacts,
                        promptMetadata,
                        requestPath,
                        resourceId,
                        httpMethod));
    }

    public String actualResourceId(
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            String requestPath,
            String resourceId,
            SealedEvidencePackage evidencePackage) {
        return firstNonBlank(
                text(requestFacts, "actualResourceId"),
                text(promptMetadata, "actualResourceId"),
                concrete(text(requestFacts, "resourceId")),
                concrete(text(requestFacts, "endpointKey")),
                concrete(text(promptMetadata, "resourceId")),
                concrete(resourceId),
                lastPathSegment(requestPath),
                evidencePackage == null ? null : evidencePackage.getPackageId());
    }

    public String resourceTemplateId(
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            ProtectableResourceDescriptor descriptor,
            String resourceId) {
        return firstNonBlank(
                text(requestFacts, "protectableResourceId"),
                text(promptMetadata, "protectableResourceId"),
                descriptor == null ? null : descriptor.resourceId(),
                template(resourceId),
                resourceId);
    }

    private ProtectableResourceDescriptor sealedEvidenceDescriptor(
            SealedEvidencePackage evidencePackage,
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            String requestPath,
            String resourceId,
            String httpMethod) {
        String resourceUrl = firstNonBlank(
                text(requestFacts, "protectableResourceUrl"),
                text(promptMetadata, "protectableResourceUrl"),
                text(requestFacts, "resourceUrl"),
                text(promptMetadata, "resourceUrl"),
                requestPath);
        String resolvedResourceId = firstNonBlank(
                text(requestFacts, "protectableResourceId"),
                text(promptMetadata, "protectableResourceId"),
                text(requestFacts, "resourceId"),
                text(promptMetadata, "resourceId"),
                resourceId,
                lastPathSegment(requestPath));
        String method = firstNonBlank(
                httpMethod,
                text(requestFacts, "httpMethod"),
                text(promptMetadata, "httpMethod"));
        if (!StringUtils.hasText(resourceUrl) && !StringUtils.hasText(resolvedResourceId)) {
            return null;
        }
        String criticality = firstNonBlank(
                text(requestFacts, "resourceSensitivity"),
                text(promptMetadata, "resourceSensitivity"),
                text(requestFacts, "sensitivity"),
                text(promptMetadata, "sensitivity"),
                "SEALED_EVIDENCE");
        String verificationValue = firstNonBlank(
                text(requestFacts, "verificationRequired"),
                text(promptMetadata, "verificationRequired"));
        boolean verificationRequired = !StringUtils.hasText(verificationValue)
                || !"false".equalsIgnoreCase(verificationValue.trim());
        return new ProtectableResourceDescriptor(
                "sealedEvidencePackage",
                "sealed-runtime-evidence:" + safe(method) + ":" + safe(firstNonBlank(resourceUrl, resolvedResourceId)),
                resolvedResourceId,
                resourceUrl,
                method,
                criticality,
                verificationRequired,
                true,
                firstNonBlank(evidencePackage == null ? null : evidencePackage.getUserId(), "sealed-runtime-evidence"));
    }

    private String lastPathSegment(String requestPath) {
        if (!StringUtils.hasText(requestPath) || containsTemplateMarker(requestPath)) {
            return null;
        }
        String normalized = requestPath.trim();
        int queryIndex = normalized.indexOf('?');
        if (queryIndex >= 0) {
            normalized = normalized.substring(0, queryIndex);
        }
        String[] parts = normalized.split("/");
        for (int index = parts.length - 1; index >= 0; index--) {
            if (StringUtils.hasText(parts[index])) {
                return parts[index].trim();
            }
        }
        return null;
    }

    private String concrete(String value) {
        return containsTemplateMarker(value) ? null : value;
    }

    private String template(String value) {
        return containsTemplateMarker(value) ? value : null;
    }

    private boolean containsTemplateMarker(String value) {
        return StringUtils.hasText(value) && value.contains("{") && value.contains("}");
    }

    private String text(Map<String, Object> values, String key) {
        if (values == null || !values.containsKey(key) || values.get(key) == null) {
            return null;
        }
        String value = String.valueOf(values.get(key)).trim();
        return value.isEmpty() ? null : value;
    }

    private String firstNonBlank(String... values) {
        if (values != null) {
            for (String value : values) {
                if (StringUtils.hasText(value)) {
                    return value.trim();
                }
            }
        }
        return null;
    }

    private String safe(String value) {
        return StringUtils.hasText(value) ? value.trim() : "";
    }
}