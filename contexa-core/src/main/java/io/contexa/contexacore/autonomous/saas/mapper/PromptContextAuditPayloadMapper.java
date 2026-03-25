package io.contexa.contexacore.autonomous.saas.mapper;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.PromptContextAuditPayload;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.std.security.AuthorizedPromptContextItem;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

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
        String tenantExternalRef = resolveTenantExternalRef(event);
        List<String> deniedReasons = resolveDeniedReasons(authorizedPromptContext);

        List<PromptContextAuditPayload.ContextItem> contexts = resolveContextItems(authorizedPromptContext);
        String contextFingerprint = resolveContextFingerprint(authorizedPromptContext, deniedReasons, contexts);
        String auditId = resolveAuditId(event, correlationId, resolvedPurpose, contextFingerprint);

        return PromptContextAuditPayload.builder()
                .auditId(auditId)
                .correlationId(correlationId)
                .tenantExternalRef(tenantExternalRef)
                .executionId(resolveExecutionId(event))
                .retrievalPurpose(resolvedPurpose)
                .contextFingerprint(contextFingerprint)
                .requestedDocumentCount(authorizedPromptContext.requestedDocumentCount())
                .allowedDocumentCount(authorizedPromptContext.allowedDocumentCount())
                .deniedDocumentCount(authorizedPromptContext.deniedDocumentCount())
                .deniedReasons(deniedReasons)
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

    private List<PromptContextAuditPayload.ContextItem> resolveContextItems(AuthorizedPromptContext authorizedPromptContext) {
        if (authorizedPromptContext.contextItems() != null && !authorizedPromptContext.contextItems().isEmpty()) {
            return authorizedPromptContext.contextItems().stream()
                    .map(this::mapContextItem)
                    .toList();
        }
        return authorizedPromptContext.documents().stream()
                .map(this::mapContextItem)
                .toList();
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

    private PromptContextAuditPayload.ContextItem mapContextItem(AuthorizedPromptContextItem item) {
        return PromptContextAuditPayload.ContextItem.builder()
                .contextType(item.contextType())
                .sourceType(item.sourceType())
                .artifactId(item.artifactId())
                .artifactVersion(item.artifactVersion())
                .authorizationDecision(item.authorizationDecision())
                .purposeMatch(item.purposeMatch())
                .provenanceSummary(item.provenanceSummary())
                .includedInPrompt(item.includedInPrompt())
                .promptSafetyDecision(item.promptSafetyDecision())
                .memoryReadDecision(item.memoryReadDecision())
                .accessScope(item.accessScope())
                .tenantBound(item.tenantBound())
                .similarityScore(item.similarityScore())
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

    private String resolveAuditId(SecurityEvent event, String correlationId, String retrievalPurpose, String contextFingerprint) {
        String eventId = StringUtils.hasText(event.getEventId()) ? event.getEventId().trim() : "unknown";
        String fingerprint = correlationId + "|" + retrievalPurpose + "|" + eventId + "|" + contextFingerprint;
        return UUID.nameUUIDFromBytes(fingerprint.getBytes(StandardCharsets.UTF_8)).toString();
    }

    private String resolveContextFingerprint(
            AuthorizedPromptContext authorizedPromptContext,
            List<String> deniedReasons,
            List<PromptContextAuditPayload.ContextItem> contexts) {
        List<String> parts = new ArrayList<>();
        parts.add("requested=" + authorizedPromptContext.requestedDocumentCount());
        parts.add("allowed=" + authorizedPromptContext.allowedDocumentCount());
        parts.add("denied=" + authorizedPromptContext.deniedDocumentCount());
        if (deniedReasons != null && !deniedReasons.isEmpty()) {
            parts.add("deniedReasons=" + String.join(",", deniedReasons));
        }
        if (contexts != null && !contexts.isEmpty()) {
            List<String> contextEntries = contexts.stream()
                    .sorted(Comparator
                            .comparing((PromptContextAuditPayload.ContextItem item) -> safeText(item.getContextType()))
                            .thenComparing(item -> safeText(item.getSourceType()))
                            .thenComparing(item -> safeText(item.getArtifactId()))
                            .thenComparing(item -> safeText(item.getArtifactVersion()))
                            .thenComparing(item -> safeText(item.getAuthorizationDecision()))
                            .thenComparing(item -> Boolean.toString(item.isIncludedInPrompt())))
                    .map(item -> String.join("|",
                            safeText(item.getContextType()),
                            safeText(item.getSourceType()),
                            safeText(item.getArtifactId()),
                            safeText(item.getArtifactVersion()),
                            safeText(item.getAuthorizationDecision()),
                            Boolean.toString(item.isIncludedInPrompt()),
                            Boolean.toString(item.isPurposeMatch()),
                            safeText(item.getAccessScope()),
                            Boolean.toString(item.isTenantBound()),
                            safeText(item.getProvenanceSummary())))
                    .toList();
            parts.addAll(contextEntries);
        }
        if (parts.isEmpty()) {
            return "no_context";
        }
        String joined = String.join(";", parts);
        return UUID.nameUUIDFromBytes(joined.getBytes(StandardCharsets.UTF_8)).toString();
    }

    private List<String> resolveDeniedReasons(AuthorizedPromptContext authorizedPromptContext) {
        if (authorizedPromptContext.deniedReasons() == null || authorizedPromptContext.deniedReasons().isEmpty()) {
            return List.of();
        }
        return authorizedPromptContext.deniedReasons().stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .sorted()
                .collect(Collectors.toUnmodifiableList());
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

    private String safeText(String value) {
        return StringUtils.hasText(value) ? value.trim() : "";
    }
}
