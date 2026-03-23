package io.contexa.contexacore.std.security;

import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import org.springframework.util.StringUtils;

import java.util.*;

public record PurposeBoundRetrievalPolicy(
        String requestUserId,
        String organizationId,
        String tenantId,
        String retrievalPurpose,
        Set<String> allowedDocumentTypes) {

    public PurposeBoundRetrievalPolicy {
        requestUserId = normalize(requestUserId);
        organizationId = normalize(organizationId);
        tenantId = normalize(tenantId);
        retrievalPurpose = normalize(retrievalPurpose);
        retrievalPurpose = StringUtils.hasText(retrievalPurpose) ? retrievalPurpose : "general_context";
        allowedDocumentTypes = normalizeTypes(allowedDocumentTypes);
    }

    public boolean allowsSourceType(String sourceType) {
        if (allowedDocumentTypes.isEmpty() || !StringUtils.hasText(sourceType)) {
            return true;
        }
        return allowedDocumentTypes.contains(sourceType.trim().toLowerCase(Locale.ROOT));
    }

    public boolean matchesPurpose(Map<String, Object> metadata) {
        Set<String> allowedPurposes = new LinkedHashSet<>();
        allowedPurposes.addAll(toLowerSet(metadata != null ? metadata.get("allowedPurposes") : null));
        allowedPurposes.addAll(toLowerSet(metadata != null ? metadata.get("allowedPurpose") : null));
        allowedPurposes.addAll(toLowerSet(metadata != null ? metadata.get(VectorDocumentMetadata.RETRIEVAL_PURPOSE) : null));
        if (allowedPurposes.isEmpty()) {
            return true;
        }
        return allowedPurposes.contains(retrievalPurpose.toLowerCase(Locale.ROOT));
    }

    public String summary() {
        String scopeSummary = String.format(
                Locale.ROOT,
                "purpose=%s,user=%s,organization=%s,tenant=%s",
                retrievalPurpose,
                fallback(requestUserId),
                fallback(organizationId),
                fallback(tenantId));
        if (allowedDocumentTypes.isEmpty()) {
            return scopeSummary + ",types=*";
        }
        return scopeSummary + ",types=" + String.join("|", allowedDocumentTypes);
    }

    private static Set<String> normalizeTypes(Set<String> values) {
        if (values == null || values.isEmpty()) {
            return Set.of();
        }
        Set<String> normalized = new LinkedHashSet<>();
        for (String value : values) {
            String candidate = normalize(value);
            if (StringUtils.hasText(candidate)) {
                normalized.add(candidate.toLowerCase(Locale.ROOT));
            }
        }
        return Set.copyOf(normalized);
    }

    private static Set<String> toLowerSet(Object raw) {
        if (raw == null) {
            return Set.of();
        }
        Collection<?> values;
        if (raw instanceof Collection<?> collection) {
            values = collection;
        }
        else if (raw instanceof Object[] array) {
            values = Arrays.asList(array);
        }
        else {
            values = Arrays.stream(raw.toString().split(",")).toList();
        }
        Set<String> normalized = new LinkedHashSet<>();
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String candidate = normalize(value.toString());
            if (StringUtils.hasText(candidate)) {
                normalized.add(candidate.toLowerCase(Locale.ROOT));
            }
        }
        return Set.copyOf(normalized);
    }

    private static String fallback(String value) {
        return StringUtils.hasText(value) ? value : "*";
    }

    private static String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }
}