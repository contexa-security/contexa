package io.contexa.contexacore.autonomous.saas.mapper;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.PromptContextAuditPayload;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class PromptContextAuditPayloadMapper {

    public PromptContextAuditPayload map(
            SecurityEvent event,
            String retrievalPurpose,
            AuthorizedPromptContext authorizedPromptContext) {
        if (event == null) {
            throw new IllegalArgumentException("SecurityEvent is required for prompt context audit");
        }
        if (authorizedPromptContext == null) {
            throw new IllegalArgumentException("AuthorizedPromptContext is required for prompt context audit");
        }

        String correlationId = resolveCorrelationId(event);
        String resolvedPurpose = StringUtils.hasText(retrievalPurpose)
                ? retrievalPurpose.trim()
                : authorizedPromptContext.retrievalPurpose();
        String auditId = resolveAuditId(event, correlationId, resolvedPurpose);

        List<PromptContextAuditPayload.ContextItem> contexts = authorizedPromptContext.documents().stream()
                .map(this::mapContextItem)
                .toList();

        return PromptContextAuditPayload.builder()
                .auditId(auditId)
                .correlationId(correlationId)
                .executionId(resolveExecutionId(event))
                .retrievalPurpose(resolvedPurpose)
                .requestedDocumentCount(authorizedPromptContext.requestedDocumentCount())
                .allowedDocumentCount(authorizedPromptContext.allowedDocumentCount())
                .deniedDocumentCount(authorizedPromptContext.deniedDocumentCount())
                .deniedReasons(authorizedPromptContext.deniedReasons())
                .contexts(contexts)
                .forwardedAt(LocalDateTime.now())
                .build();
    }

    public String resolveTenantExternalRef(SecurityEvent event) {
        if (event != null && event.getMetadata() != null) {
            Object tenantId = event.getMetadata().get("tenantId");
            if (tenantId instanceof String value && !value.isBlank()) {
                return value.trim();
            }
            Object organizationId = event.getMetadata().get("organizationId");
            if (organizationId instanceof String value && !value.isBlank()) {
                return value.trim();
            }
        }
        return "default";
    }

    private PromptContextAuditPayload.ContextItem mapContextItem(Document document) {
        Map<String, Object> metadata = document.getMetadata() != null ? document.getMetadata() : Map.of();
        return PromptContextAuditPayload.ContextItem.builder()
                .contextType(resolveText(metadata,
                        VectorDocumentMetadata.SOURCE_TYPE,
                        VectorDocumentMetadata.DOCUMENT_TYPE,
                        "contextType",
                        "type"))
                .sourceType(resolveText(metadata,
                        VectorDocumentMetadata.SOURCE_TYPE,
                        VectorDocumentMetadata.DOCUMENT_TYPE,
                        "sourceType"))
                .artifactId(resolveText(metadata,
                        VectorDocumentMetadata.ARTIFACT_ID,
                        VectorDocumentMetadata.ORIGINAL_DOCUMENT_ID,
                        VectorDocumentMetadata.ID,
                        VectorDocumentMetadata.EVENT_ID))
                .artifactVersion(resolveText(metadata,
                        VectorDocumentMetadata.ARTIFACT_VERSION,
                        VectorDocumentMetadata.VERSION))
                .authorizationDecision(resolveText(metadata,
                        VectorDocumentMetadata.AUTHORIZATION_DECISION,
                        "authorizationDecision"))
                .purposeMatch(resolveBoolean(metadata.get(VectorDocumentMetadata.PURPOSE_MATCH)))
                .provenanceSummary(resolveText(metadata,
                        VectorDocumentMetadata.PROVENANCE_SUMMARY,
                        "provenanceSummary"))
                .includedInPrompt(true)
                .promptSafetyDecision(resolveText(metadata,
                        VectorDocumentMetadata.PROMPT_SAFETY_DECISION,
                        "promptSafetyDecision"))
                .memoryReadDecision(resolveText(metadata,
                        VectorDocumentMetadata.MEMORY_READ_DECISION,
                        "memoryReadDecision"))
                .accessScope(resolveText(metadata,
                        VectorDocumentMetadata.ACCESS_SCOPE,
                        VectorDocumentMetadata.SHARE_SCOPE,
                        "accessScope"))
                .tenantBound(resolveBoolean(metadata.get(VectorDocumentMetadata.TENANT_BOUND)))
                .similarityScore(resolveDouble(metadata.get(VectorDocumentMetadata.SIMILARITY_SCORE), document.getScore()))
                .build();
    }

    private String resolveCorrelationId(SecurityEvent event) {
        if (event.getMetadata() != null) {
            Object correlationId = event.getMetadata().get("correlationId");
            if (correlationId instanceof String value && !value.isBlank()) {
                return value.trim();
            }
        }
        if (StringUtils.hasText(event.getEventId())) {
            return event.getEventId().trim();
        }
        return UUID.randomUUID().toString();
    }

    private String resolveAuditId(SecurityEvent event, String correlationId, String retrievalPurpose) {
        String eventId = StringUtils.hasText(event.getEventId()) ? event.getEventId().trim() : "unknown";
        String fingerprint = correlationId + "|" + retrievalPurpose + "|" + eventId;
        return UUID.nameUUIDFromBytes(fingerprint.getBytes(StandardCharsets.UTF_8)).toString();
    }

    private String resolveExecutionId(SecurityEvent event) {
        if (event.getMetadata() == null) {
            return null;
        }
        Object executionId = event.getMetadata().get("executionId");
        if (executionId instanceof String value && !value.isBlank()) {
            return value.trim();
        }
        Object delegatedExecution = event.getMetadata().get("delegatedExecution");
        if (delegatedExecution instanceof Map<?, ?> metadata) {
            Object nestedExecutionId = metadata.get("executionId");
            if (nestedExecutionId instanceof String value && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private boolean resolveBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            return Boolean.parseBoolean(text.trim());
        }
        return false;
    }

    private Double resolveDouble(Object value, Double fallback) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            try {
                return Double.parseDouble(text.trim());
            }
            catch (NumberFormatException ignored) {
                return fallback;
            }
        }
        return fallback;
    }

    private String resolveText(Map<String, Object> metadata, String... keys) {
        for (String key : keys) {
            Object value = metadata.get(key);
            if (value != null && StringUtils.hasText(value.toString())) {
                return value.toString().trim();
            }
        }
        return null;
    }
}
