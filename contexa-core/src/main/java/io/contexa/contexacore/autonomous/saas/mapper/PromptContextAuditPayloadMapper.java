/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.saas.mapper;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.PromptContextAuditPayload;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.std.security.AuthorizedPromptContextItem;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
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

        List<PromptContextAuditPayload.ContextItem> contexts = resolveContextItems(authorizedPromptContext, resolvedPurpose);
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
                .promptKey(resolvePromptKey(event))
                .templateKey(resolveTemplateKey(event))
                .promptVersion(resolvePromptVersion(event))
                .promptHash(resolvePromptHash(event))
                .systemPromptHash(resolveSystemPromptHash(event))
                .userPromptHash(resolveUserPromptHash(event))
                .systemPrompt(null)
                .userPrompt(null)
                .resourceId(resolveResourceId(event))
                .requestPath(resolveRequestPath(event))
                .promptRuntimeTelemetryLinked(resolvePromptRuntimeTelemetryLinked(event))
                .promptRuntimeTelemetryLayer(resolvePromptRuntimeTelemetryLayer(event))
                .promptRuntimeTelemetry(resolvePromptRuntimeTelemetry(event))
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

    public PromptContextAuditPayload enrich(PromptContextAuditPayload payload, SecurityEvent event) {
        if (payload == null || event == null) {
            return payload;
        }
        return PromptContextAuditPayload.builder()
                .auditId(payload.getAuditId())
                .correlationId(firstNonBlank(resolveCorrelationId(event), payload.getCorrelationId()))
                .tenantExternalRef(firstNonBlank(resolveTenantExternalRef(event), payload.getTenantExternalRef()))
                .executionId(firstNonBlank(resolveExecutionId(event), payload.getExecutionId()))
                .retrievalPurpose(firstNonBlank(payload.getRetrievalPurpose(), resolveText(metadata(event), "retrievalPurpose")))
                .contextFingerprint(payload.getContextFingerprint())
                .requestedDocumentCount(payload.getRequestedDocumentCount())
                .allowedDocumentCount(payload.getAllowedDocumentCount())
                .deniedDocumentCount(payload.getDeniedDocumentCount())
                .deniedReasons(payload.getDeniedReasons() == null ? List.of() : List.copyOf(payload.getDeniedReasons()))
                .contexts(payload.getContexts() == null ? List.of() : List.copyOf(payload.getContexts()))
                .promptKey(firstNonBlank(resolvePromptKey(event), payload.getPromptKey()))
                .templateKey(firstNonBlank(resolveTemplateKey(event), payload.getTemplateKey()))
                .promptVersion(firstNonBlank(resolvePromptVersion(event), payload.getPromptVersion()))
                .promptHash(firstNonBlank(resolvePromptHash(event), payload.getPromptHash()))
                .systemPromptHash(firstNonBlank(resolveSystemPromptHash(event), payload.getSystemPromptHash()))
                .userPromptHash(firstNonBlank(resolveUserPromptHash(event), payload.getUserPromptHash()))
                .systemPrompt(null)
                .userPrompt(null)
                .resourceId(firstNonBlank(resolveResourceId(event), payload.getResourceId()))
                .requestPath(firstNonBlank(resolveRequestPath(event), payload.getRequestPath()))
                .promptRuntimeTelemetryLinked(metadata(event).containsKey("promptRuntimeTelemetryLinked")
                        ? resolveBoolean(metadata(event).get("promptRuntimeTelemetryLinked"))
                        : payload.getPromptRuntimeTelemetryLinked())
                .promptRuntimeTelemetryLayer(firstNonBlank(resolvePromptRuntimeTelemetryLayer(event), payload.getPromptRuntimeTelemetryLayer()))
                .promptRuntimeTelemetry(mergePromptRuntimeTelemetry(payload.getPromptRuntimeTelemetry(), resolvePromptRuntimeTelemetry(event)))
                .forwardedAt(payload.getForwardedAt() != null ? payload.getForwardedAt() : LocalDateTime.now())
                .build();
    }

    private Map<String, Object> metadata(SecurityEvent event) {
        return event != null && event.getMetadata() != null ? event.getMetadata() : Map.of();
    }

    private String resolvePromptKey(SecurityEvent event) {
        return resolveText(metadata(event), "promptKey");
    }

    private String resolveTemplateKey(SecurityEvent event) {
        return resolveText(metadata(event), "templateKey", "promptTemplateKey");
    }

    private String resolvePromptVersion(SecurityEvent event) {
        return resolveText(metadata(event), "promptVersion");
    }

    private String resolvePromptHash(SecurityEvent event) {
        return resolveText(metadata(event), "promptHash");
    }

    private String resolveSystemPromptHash(SecurityEvent event) {
        return resolveText(metadata(event), "systemPromptHash");
    }

    private String resolveUserPromptHash(SecurityEvent event) {
        return resolveText(metadata(event), "userPromptHash");
    }

    private String resolveSystemPrompt(SecurityEvent event) {
        return resolveText(metadata(event), "systemPrompt");
    }

    private String resolveUserPrompt(SecurityEvent event) {
        return resolveText(metadata(event), "userPrompt");
    }

    private String resolveResourceId(SecurityEvent event) {
        return resolveText(metadata(event), "resourceId");
    }

    private String resolveRequestPath(SecurityEvent event) {
        return resolveText(metadata(event), "requestPath", "requestUri", "servletPath");
    }

    private String resolvePromptRuntimeTelemetryLayer(SecurityEvent event) {
        return resolveText(metadata(event), "promptRuntimeTelemetryLayer");
    }

    private Boolean resolvePromptRuntimeTelemetryLinked(SecurityEvent event) {
        if (!metadata(event).containsKey("promptRuntimeTelemetryLinked")) {
            return null;
        }
        return resolveBoolean(metadata(event).get("promptRuntimeTelemetryLinked"));
    }

    private Map<String, Object> resolvePromptRuntimeTelemetry(SecurityEvent event) {
        Map<String, Object> telemetry = PromptRuntimeTelemetrySupport.extractRuntimeTelemetry(metadata(event));
        return telemetry.isEmpty() ? Map.of() : Map.copyOf(telemetry);
    }

    private Map<String, Object> mergePromptRuntimeTelemetry(
            Map<String, Object> existing,
            Map<String, Object> resolved
    ) {
        Map<String, Object> merged = new LinkedHashMap<>();
        if (existing != null && !existing.isEmpty()) {
            merged.putAll(existing);
        }
        if (resolved != null && !resolved.isEmpty()) {
            resolved.forEach(merged::putIfAbsent);
        }
        return merged.isEmpty() ? Map.of() : Map.copyOf(merged);
    }
    private List<PromptContextAuditPayload.ContextItem> resolveContextItems(
            AuthorizedPromptContext authorizedPromptContext,
            String retrievalPurpose) {
        if (authorizedPromptContext.contextItems() != null && !authorizedPromptContext.contextItems().isEmpty()) {
            return authorizedPromptContext.contextItems().stream()
                    .map(item -> mapContextItem(item, retrievalPurpose))
                    .toList();
        }
        return authorizedPromptContext.documents().stream()
                .map(document -> mapContextItem(document, retrievalPurpose))
                .toList();
    }

    private PromptContextAuditPayload.ContextItem mapContextItem(Document document, String retrievalPurpose) {
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
                .userId(resolveText(metadata,
                        VectorDocumentMetadata.USER_ID,
                        "userId"))
                .retrievalPurpose(resolveText(metadata,
                        VectorDocumentMetadata.RETRIEVAL_PURPOSE,
                        "retrievalPurpose",
                        retrievalPurpose))
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

    private PromptContextAuditPayload.ContextItem mapContextItem(
            AuthorizedPromptContextItem item,
            String retrievalPurpose) {
        return PromptContextAuditPayload.ContextItem.builder()
                .contextType(item.contextType())
                .sourceType(item.sourceType())
                .artifactId(item.artifactId())
                .artifactVersion(item.artifactVersion())
                .userId(item.userId())
                .retrievalPurpose(StringUtils.hasText(item.retrievalPurpose()) ? item.retrievalPurpose() : retrievalPurpose)
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

    public String resolveCorrelationId(SecurityEvent event) {
        if (event.getMetadata() != null) {
            Object correlationId = event.getMetadata().get("correlationId");
            if (correlationId instanceof String value && !value.isBlank()) {
                return value.trim();
            }
            Object requestId = event.getMetadata().get("requestId");
            if (requestId instanceof String value && !value.isBlank()) {
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

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }
    private String safeText(String value) {
        return StringUtils.hasText(value) ? value.trim() : "";
    }
}

