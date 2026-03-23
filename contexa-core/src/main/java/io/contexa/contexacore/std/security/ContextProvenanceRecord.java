package io.contexa.contexacore.std.security;

import org.springframework.util.StringUtils;

import java.util.Locale;

public record ContextProvenanceRecord(
        String artifactId,
        String artifactVersion,
        String sourceType,
        String accessScope,
        boolean tenantBound,
        String retrievalPurpose,
        boolean purposeMatch,
        String summary) {

    public ContextProvenanceRecord {
        artifactId = normalize(artifactId);
        artifactVersion = normalize(artifactVersion);
        sourceType = normalize(sourceType);
        accessScope = normalize(accessScope);
        retrievalPurpose = normalize(retrievalPurpose);
        summary = StringUtils.hasText(summary)
                ? summary.trim()
                : String.format(
                        Locale.ROOT,
                        "source=%s,scope=%s,artifact=%s,purpose=%s,match=%s,tenantBound=%s",
                        fallback(sourceType),
                        fallback(accessScope),
                        fallback(artifactId),
                        fallback(retrievalPurpose),
                        purposeMatch,
                        tenantBound);
    }

    private static String fallback(String value) {
        return StringUtils.hasText(value) ? value : "unknown";
    }

    private static String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }
}