package io.contexa.contexacore.std.security;

import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class MemoryReadPolicy {

    private static final Set<String> RUNTIME_APPROVED_STATES = Set.of(
            "PROMOTED",
            "VALIDATED",
            "APPROVED",
            "RUNTIME_APPROVED",
            "ACTIVE");
    private static final Set<String> QUARANTINED_STATES = Set.of(
            "QUARANTINED",
            "BLOCKED",
            "UNTRUSTED",
            "ISOLATED");

    public MemoryReadDecision evaluate(Document document) {
        if (document == null) {
            return MemoryReadDecision.deny("DENIED_MEMORY_MISSING");
        }

        Map<String, Object> metadata = document.getMetadata() != null ? document.getMetadata() : Map.of();
        if (!isMemoryDocument(metadata)) {
            return MemoryReadDecision.allow("ALLOWED_STANDARD_CONTEXT");
        }

        String quarantineState = normalize(first(metadata,
                "memorySafetyStatus",
                "quarantineState",
                "quarantine_status"));
        if (quarantineState != null && QUARANTINED_STATES.contains(quarantineState)) {
            return MemoryReadDecision.deny("DENIED_MEMORY_QUARANTINED");
        }

        Object runtimeSafe = metadata.get("runtimeSafe");
        if (runtimeSafe instanceof Boolean safe && safe) {
            return MemoryReadDecision.allow("ALLOWED_MEMORY_RUNTIME_SAFE");
        }

        String promotionState = normalize(first(metadata,
                "promotionState",
                "promotion_state",
                "artifactState",
                "artifact_state"));
        if (promotionState != null && RUNTIME_APPROVED_STATES.contains(promotionState)) {
            return MemoryReadDecision.allow("ALLOWED_MEMORY_PROMOTED");
        }

        return MemoryReadDecision.deny("DENIED_MEMORY_PROMOTION");
    }

    private boolean isMemoryDocument(Map<String, Object> metadata) {
        String documentType = normalize(first(metadata,
                VectorDocumentMetadata.DOCUMENT_TYPE,
                VectorDocumentMetadata.SOURCE_TYPE,
                "documentType",
                "sourceType"));
        if (VectorDocumentType.MEMORY_LTM.getValue().equalsIgnoreCase(documentType)) {
            return true;
        }
        Object explicit = metadata.get("memoryArtifact");
        return explicit instanceof Boolean value && value;
    }

    private String first(Map<String, Object> metadata, String... keys) {
        for (String key : keys) {
            Object value = metadata.get(key);
            if (value != null && StringUtils.hasText(value.toString())) {
                return value.toString();
            }
        }
        return null;
    }

    private String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim().toUpperCase(Locale.ROOT) : null;
    }
}