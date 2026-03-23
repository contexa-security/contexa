package io.contexa.contexacore.std.security;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import org.springframework.ai.document.Document;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.util.*;

public class PromptContextAuthorizationService {

    private static final String ACCESS_SCOPE_USER = "USER";
    private static final String ACCESS_SCOPE_ORGANIZATION = "ORGANIZATION";
    private static final String ACCESS_SCOPE_GLOBAL = "GLOBAL";
    private static final String PURPOSE_SECURITY_INVESTIGATION = "security_investigation";

    private final PromptSafetyGuardService promptSafetyGuardService;
    private final MemoryReadPolicy memoryReadPolicy;
    private final PromptInjectionDefenseService promptInjectionDefenseService;
    private final MemoryQuarantineService memoryQuarantineService;
    private final KnowledgeQuarantineService knowledgeQuarantineService;

    public PromptContextAuthorizationService() {
        this(new PromptSafetyGuardService(), new MemoryReadPolicy());
    }

    public PromptContextAuthorizationService(
            PromptSafetyGuardService promptSafetyGuardService,
            MemoryReadPolicy memoryReadPolicy) {
        this.promptSafetyGuardService = promptSafetyGuardService != null ? promptSafetyGuardService : new PromptSafetyGuardService();
        this.memoryReadPolicy = memoryReadPolicy != null ? memoryReadPolicy : new MemoryReadPolicy();
        this.promptInjectionDefenseService = new PromptInjectionDefenseService(this.promptSafetyGuardService, new PromptContextSanitizer());
        this.memoryQuarantineService = new MemoryQuarantineService(this.memoryReadPolicy);
        this.knowledgeQuarantineService = new KnowledgeQuarantineService(new PoisonedKnowledgeIncidentService());
    }

    public AuthorizedPromptContext authorize(AIRequest<? extends DomainContext> request, List<Document> documents) {
        DomainContext context = request != null ? request.getContext() : null;
        AuthorizationScope scope = new AuthorizationScope(
                resolveUserId(request, context),
                resolveOrganizationId(request, context),
                resolveTenantId(request, context),
                normalize(resolveRetrievalPurpose(request)),
                resolveAllowedDocumentTypes(request));
        return authorize(scope, documents);
    }

    public AuthorizedPromptContext authorize(SecurityEvent event, @Nullable String retrievalPurpose, List<Document> documents) {
        Map<String, Object> metadata = event != null && event.getMetadata() != null ? event.getMetadata() : Map.of();
        AuthorizationScope scope = new AuthorizationScope(
                normalize(event != null ? event.getUserId() : null),
                normalize(resolveText(metadata, "organizationId", "organization_id")),
                normalize(resolveText(metadata, "tenantId", "tenant_id")),
                normalize(StringUtils.hasText(retrievalPurpose) ? retrievalPurpose : PURPOSE_SECURITY_INVESTIGATION),
                Set.of());
        return authorize(scope, documents);
    }

    private AuthorizedPromptContext authorize(AuthorizationScope scope, List<Document> documents) {
        PurposeBoundRetrievalPolicy retrievalPolicy = new PurposeBoundRetrievalPolicy(
                scope.requestUserId(),
                scope.organizationId(),
                scope.tenantId(),
                scope.retrievalPurpose(),
                scope.allowedDocumentTypes());
        if (documents == null || documents.isEmpty()) {
            return new AuthorizedPromptContext(List.of(), 0, 0, 0, scope.retrievalPurpose(), List.of(), retrievalPolicy, List.of());
        }

        List<Document> allowed = new ArrayList<>();
        List<String> deniedReasons = new ArrayList<>();
        List<ContextProvenanceRecord> provenanceRecords = new ArrayList<>();
        for (Document document : documents) {
            ContextAuthorizationDecision decision = evaluate(scope, retrievalPolicy, document);
            provenanceRecords.add(decision.provenanceRecord());
            if (decision.allowed()) {
                allowed.add(decorateDocument(document, decision, retrievalPolicy));
            }
            else {
                deniedReasons.add(decision.decision());
            }
        }

        return new AuthorizedPromptContext(
                allowed,
                documents.size(),
                allowed.size(),
                documents.size() - allowed.size(),
                scope.retrievalPurpose(),
                deniedReasons,
                retrievalPolicy,
                provenanceRecords);
    }

    private ContextAuthorizationDecision evaluate(AuthorizationScope scope, PurposeBoundRetrievalPolicy retrievalPolicy, Document document) {
        Map<String, Object> metadata = document.getMetadata() != null ? document.getMetadata() : Map.of();
        String sourceType = normalize(resolveText(metadata,
                VectorDocumentMetadata.SOURCE_TYPE,
                VectorDocumentMetadata.DOCUMENT_TYPE,
                "type"));
        String accessScope = resolveAccessScope(metadata);
        String tenantId = normalize(resolveText(metadata, VectorDocumentMetadata.TENANT_ID, "tenantId", "tenant_id"));
        String organizationId = normalize(resolveText(metadata, VectorDocumentMetadata.ORGANIZATION_ID, "organizationId", "organization_id"));
        String documentUserId = normalize(resolveText(metadata, VectorDocumentMetadata.USER_ID, "userId"));
        String artifactId = normalize(resolveText(metadata,
                VectorDocumentMetadata.ARTIFACT_ID,
                VectorDocumentMetadata.ORIGINAL_DOCUMENT_ID,
                VectorDocumentMetadata.ID,
                VectorDocumentMetadata.EVENT_ID));
        String artifactVersion = normalize(resolveText(metadata, VectorDocumentMetadata.ARTIFACT_VERSION, VectorDocumentMetadata.VERSION));
        String provenanceSummary = resolveProvenanceSummary(metadata, sourceType, accessScope, artifactId);
        boolean tenantBound = tenantBound(metadata, tenantId, organizationId);
        boolean purposeMatch = retrievalPolicy.matchesPurpose(metadata);
        ContextProvenanceRecord provenanceRecord = new ContextProvenanceRecord(
                artifactId,
                artifactVersion,
                sourceType,
                accessScope,
                tenantBound,
                scope.retrievalPurpose(),
                purposeMatch,
                provenanceSummary);
        boolean sourceTypeAllowed = retrievalPolicy.allowsSourceType(sourceType);

        if (!sourceTypeAllowed) {
            return decision(false, "DENIED_SOURCE_TYPE", purposeMatch, sourceType, accessScope, tenantBound, artifactId, artifactVersion, provenanceSummary, provenanceRecord, null, null, null);
        }
        if (!purposeMatch) {
            return decision(false, "DENIED_PURPOSE", false, sourceType, accessScope, tenantBound, artifactId, artifactVersion, provenanceSummary, provenanceRecord, null, null, null);
        }
        if (tenantBound && !matchesTenantScope(scope, tenantId, organizationId)) {
            return decision(false, "DENIED_TENANT_SCOPE", true, sourceType, accessScope, tenantBound, artifactId, artifactVersion, provenanceSummary, provenanceRecord, null, null, null);
        }
        if (ACCESS_SCOPE_USER.equals(accessScope) && !matchesUserScope(scope.requestUserId(), documentUserId)) {
            return decision(false, "DENIED_USER_SCOPE", true, sourceType, accessScope, tenantBound, artifactId, artifactVersion, provenanceSummary, provenanceRecord, null, null, null);
        }
        if (ACCESS_SCOPE_ORGANIZATION.equals(accessScope) && !matchesOrganizationScope(scope, tenantId, organizationId)) {
            return decision(false, "DENIED_ORGANIZATION_SCOPE", true, sourceType, accessScope, tenantBound, artifactId, artifactVersion, provenanceSummary, provenanceRecord, null, null, null);
        }
        PromptInjectionDefenseService.PromptInjectionDefenseDecision promptDefenseDecision = promptInjectionDefenseService.evaluate(document);
        MemoryQuarantineService.MemoryQuarantineDecision memoryQuarantineDecision = memoryQuarantineService.evaluate(document);
        KnowledgeQuarantineService.KnowledgeQuarantineDecision knowledgeQuarantineDecision = knowledgeQuarantineService.evaluate(
                provenanceRecord,
                promptDefenseDecision,
                memoryQuarantineDecision);

        if (!promptDefenseDecision.allowed()) {
            return decision(
                    false,
                    promptDefenseDecision.decision(),
                    true,
                    sourceType,
                    accessScope,
                    tenantBound,
                    artifactId,
                    artifactVersion,
                    provenanceSummary,
                    provenanceRecord,
                    promptDefenseDecision,
                    memoryQuarantineDecision,
                    knowledgeQuarantineDecision);
        }
        if (!memoryQuarantineDecision.allowed()) {
            return decision(
                    false,
                    memoryQuarantineDecision.decision(),
                    true,
                    sourceType,
                    accessScope,
                    tenantBound,
                    artifactId,
                    artifactVersion,
                    provenanceSummary,
                    provenanceRecord,
                    promptDefenseDecision,
                    memoryQuarantineDecision,
                    knowledgeQuarantineDecision);
        }
        if (!knowledgeQuarantineDecision.allowed()) {
            return decision(
                    false,
                    knowledgeQuarantineDecision.decision(),
                    true,
                    sourceType,
                    accessScope,
                    tenantBound,
                    artifactId,
                    artifactVersion,
                    provenanceSummary,
                    provenanceRecord,
                    promptDefenseDecision,
                    memoryQuarantineDecision,
                    knowledgeQuarantineDecision);
        }

        String decision = switch (accessScope) {
            case ACCESS_SCOPE_USER -> "ALLOWED_USER_SCOPE";
            case ACCESS_SCOPE_ORGANIZATION -> "ALLOWED_ORGANIZATION_SCOPE";
            default -> "ALLOWED_GLOBAL_SCOPE";
        };
        return decision(
                true,
                decision,
                true,
                sourceType,
                accessScope,
                tenantBound,
                artifactId,
                artifactVersion,
                provenanceSummary,
                provenanceRecord,
                promptDefenseDecision,
                memoryQuarantineDecision,
                knowledgeQuarantineDecision);
    }

    private ContextAuthorizationDecision decision(
            boolean allowed,
            String decision,
            boolean purposeMatch,
            String sourceType,
            String accessScope,
            boolean tenantBound,
            String artifactId,
            String artifactVersion,
            String provenanceSummary,
            ContextProvenanceRecord provenanceRecord,
            PromptInjectionDefenseService.PromptInjectionDefenseDecision promptDefenseDecision,
            MemoryQuarantineService.MemoryQuarantineDecision memoryQuarantineDecision,
            KnowledgeQuarantineService.KnowledgeQuarantineDecision knowledgeQuarantineDecision) {
        return new ContextAuthorizationDecision(
                allowed,
                decision,
                purposeMatch,
                sourceType,
                accessScope,
                tenantBound,
                artifactId,
                artifactVersion,
                provenanceSummary,
                provenanceRecord,
                promptDefenseDecision != null ? promptDefenseDecision.decision() : null,
                promptDefenseDecision != null ? promptDefenseDecision.flags() : List.of(),
                promptDefenseDecision != null ? promptDefenseDecision.quarantineState() : null,
                memoryQuarantineDecision != null ? memoryQuarantineDecision.decision() : null,
                knowledgeQuarantineDecision != null ? knowledgeQuarantineDecision.quarantineState() : null,
                knowledgeQuarantineDecision != null ? knowledgeQuarantineDecision.incidentSummary() : null,
                knowledgeQuarantineDecision != null ? knowledgeQuarantineDecision.incidentFacts() : List.of(),
                promptDefenseDecision != null ? promptDefenseDecision.sanitizedText() : null);
    }

    private Document decorateDocument(Document document, ContextAuthorizationDecision decision, PurposeBoundRetrievalPolicy retrievalPolicy) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        if (document.getMetadata() != null) {
            metadata.putAll(document.getMetadata());
        }
        if (document.getScore() != null && !metadata.containsKey(VectorDocumentMetadata.SIMILARITY_SCORE)) {
            metadata.put(VectorDocumentMetadata.SIMILARITY_SCORE, document.getScore());
        }
        metadata.put(VectorDocumentMetadata.AUTHORIZATION_DECISION, decision.decision());
        metadata.put(VectorDocumentMetadata.PURPOSE_MATCH, decision.purposeMatch());
        metadata.put(VectorDocumentMetadata.RETRIEVAL_PURPOSE, retrievalPolicy.retrievalPurpose());
        metadata.put(VectorDocumentMetadata.RETRIEVAL_POLICY_SUMMARY, retrievalPolicy.summary());
        putIfText(metadata, VectorDocumentMetadata.SOURCE_TYPE, decision.sourceType());
        putIfText(metadata, VectorDocumentMetadata.ACCESS_SCOPE, decision.accessScope());
        metadata.put(VectorDocumentMetadata.TENANT_BOUND, decision.tenantBound());
        putIfText(metadata, VectorDocumentMetadata.ARTIFACT_ID, decision.artifactId());
        putIfText(metadata, VectorDocumentMetadata.ARTIFACT_VERSION, decision.artifactVersion());
        putIfText(metadata, VectorDocumentMetadata.PROVENANCE_SUMMARY, decision.provenanceSummary());
        putIfText(metadata, VectorDocumentMetadata.PROVENANCE_SOURCE_TYPE, decision.provenanceRecord().sourceType());
        putIfText(metadata, VectorDocumentMetadata.PROVENANCE_ACCESS_SCOPE, decision.provenanceRecord().accessScope());
        putIfText(metadata, VectorDocumentMetadata.PROVENANCE_ARTIFACT_ID, decision.provenanceRecord().artifactId());
        putIfText(metadata, VectorDocumentMetadata.PROVENANCE_ARTIFACT_VERSION, decision.provenanceRecord().artifactVersion());
        putIfText(metadata, VectorDocumentMetadata.PROVENANCE_RETRIEVAL_PURPOSE, decision.provenanceRecord().retrievalPurpose());
        metadata.put(VectorDocumentMetadata.PROVENANCE_PURPOSE_MATCH, decision.provenanceRecord().purposeMatch());
        metadata.put(VectorDocumentMetadata.PROVENANCE_TENANT_BOUND, decision.provenanceRecord().tenantBound());
        putIfText(metadata, VectorDocumentMetadata.PROMPT_SAFETY_DECISION, decision.promptSafetyDecision());
        putIfText(metadata, VectorDocumentMetadata.PROMPT_QUARANTINE_STATE, decision.promptQuarantineState());
        putIfText(metadata, VectorDocumentMetadata.MEMORY_READ_DECISION, decision.memoryReadDecision());
        putIfText(metadata, VectorDocumentMetadata.KNOWLEDGE_QUARANTINE_STATE, decision.knowledgeQuarantineState());
        putIfText(metadata, VectorDocumentMetadata.KNOWLEDGE_INCIDENT_SUMMARY, decision.knowledgeIncidentSummary());
        if (!decision.promptSafetyFlags().isEmpty()) {
            metadata.put(VectorDocumentMetadata.PROMPT_SAFETY_FLAGS, String.join(",", decision.promptSafetyFlags()));
        }
        if (!decision.knowledgeIncidentFacts().isEmpty()) {
            metadata.put(VectorDocumentMetadata.KNOWLEDGE_INCIDENT_FACTS, String.join(",", decision.knowledgeIncidentFacts()));
        }
        if (!metadata.containsKey(VectorDocumentMetadata.SHARE_SCOPE)) {
            metadata.put(VectorDocumentMetadata.SHARE_SCOPE, decision.accessScope());
        }
        String runtimeText = StringUtils.hasText(decision.runtimeText()) ? decision.runtimeText() : document.getText();
        return new Document(runtimeText, metadata);
    }

    private void putIfText(Map<String, Object> metadata, String key, String value) {
        if (StringUtils.hasText(value)) {
            metadata.put(key, value);
        }
    }

    private String resolveAccessScope(Map<String, Object> metadata) {
        String explicit = normalize(resolveText(metadata,
                VectorDocumentMetadata.ACCESS_SCOPE,
                VectorDocumentMetadata.SHARE_SCOPE,
                "accessScope",
                "shareScope"));
        if (StringUtils.hasText(explicit)) {
            return explicit.toUpperCase(Locale.ROOT);
        }
        if (StringUtils.hasText(resolveText(metadata, VectorDocumentMetadata.USER_ID, "userId"))) {
            return ACCESS_SCOPE_USER;
        }
        if (StringUtils.hasText(resolveText(metadata, VectorDocumentMetadata.TENANT_ID, VectorDocumentMetadata.ORGANIZATION_ID, "tenantId", "organizationId"))) {
            return ACCESS_SCOPE_ORGANIZATION;
        }
        return ACCESS_SCOPE_GLOBAL;
    }

    private boolean tenantBound(Map<String, Object> metadata, String tenantId, String organizationId) {
        Object explicit = metadata.get(VectorDocumentMetadata.TENANT_BOUND);
        if (explicit instanceof Boolean bound) {
            return bound;
        }
        return StringUtils.hasText(tenantId) || StringUtils.hasText(organizationId);
    }

    private boolean matchesTenantScope(AuthorizationScope scope, String tenantId, String organizationId) {
        if (!StringUtils.hasText(tenantId) && !StringUtils.hasText(organizationId)) {
            return true;
        }
        if (StringUtils.hasText(tenantId) && StringUtils.hasText(scope.tenantId())) {
            return tenantId.equalsIgnoreCase(scope.tenantId());
        }
        if (StringUtils.hasText(organizationId) && StringUtils.hasText(scope.organizationId())) {
            return organizationId.equalsIgnoreCase(scope.organizationId());
        }
        return false;
    }

    private boolean matchesOrganizationScope(AuthorizationScope scope, String tenantId, String organizationId) {
        if (StringUtils.hasText(organizationId) && StringUtils.hasText(scope.organizationId())) {
            return organizationId.equalsIgnoreCase(scope.organizationId());
        }
        if (StringUtils.hasText(tenantId) && StringUtils.hasText(scope.tenantId())) {
            return tenantId.equalsIgnoreCase(scope.tenantId());
        }
        return true;
    }

    private boolean matchesUserScope(String requestUserId, String documentUserId) {
        return StringUtils.hasText(requestUserId)
                && StringUtils.hasText(documentUserId)
                && requestUserId.equalsIgnoreCase(documentUserId);
    }

    private String resolveProvenanceSummary(Map<String, Object> metadata, String sourceType, String accessScope, String artifactId) {
        String explicit = normalize(resolveText(metadata, VectorDocumentMetadata.PROVENANCE_SUMMARY, "provenanceSummary"));
        if (StringUtils.hasText(explicit)) {
            return explicit;
        }
        List<String> parts = new ArrayList<>();
        if (StringUtils.hasText(sourceType)) {
            parts.add("source=" + sourceType);
        }
        if (StringUtils.hasText(accessScope)) {
            parts.add("scope=" + accessScope);
        }
        if (StringUtils.hasText(artifactId)) {
            parts.add("artifact=" + artifactId);
        }
        return parts.isEmpty() ? "core_context" : String.join(", ", parts);
    }

    private String resolveUserId(AIRequest<? extends DomainContext> request, DomainContext context) {
        String explicit = normalize(resolveParameter(request, "userId"));
        if (StringUtils.hasText(explicit)) {
            return explicit;
        }
        return context != null ? normalize(context.getUserId()) : null;
    }

    private String resolveOrganizationId(AIRequest<? extends DomainContext> request, DomainContext context) {
        String explicit = normalize(resolveParameter(request, "organizationId"));
        if (StringUtils.hasText(explicit)) {
            return explicit;
        }
        return context != null ? normalize(context.getOrganizationId()) : null;
    }

    private String resolveTenantId(AIRequest<? extends DomainContext> request, DomainContext context) {
        String explicit = normalize(resolveParameter(request, "tenantId"));
        if (StringUtils.hasText(explicit)) {
            return explicit;
        }
        if (context != null) {
            return normalize(resolveText(context.getAllMetadata(), "tenantId", "tenant_id"));
        }
        return null;
    }

    private String resolveRetrievalPurpose(AIRequest<? extends DomainContext> request) {
        String explicit = normalize(resolveParameter(request, "retrievalPurpose"));
        return StringUtils.hasText(explicit) ? explicit : "general_context";
    }

    private Set<String> resolveAllowedDocumentTypes(AIRequest<? extends DomainContext> request) {
        Object raw = request != null ? request.getParameters().get("allowedDocumentTypes") : null;
        return toLowerSet(raw);
    }

    private String resolveParameter(AIRequest<? extends DomainContext> request, String key) {
        if (request == null || key == null) {
            return null;
        }
        Object value = request.getParameters().get(key);
        return value != null ? value.toString() : null;
    }

    private Set<String> toLowerSet(@Nullable Object raw) {
        if (raw == null) {
            return new LinkedHashSet<>();
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
            String text = normalize(value.toString());
            if (StringUtils.hasText(text)) {
                normalized.add(text.toLowerCase(Locale.ROOT));
            }
        }
        return normalized;
    }

    private String resolveText(Map<String, Object> metadata, String... keys) {
        if (metadata == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            Object value = metadata.get(key);
            if (value != null && StringUtils.hasText(value.toString())) {
                return value.toString();
            }
        }
        return null;
    }

    private String normalize(@Nullable String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }

    private record AuthorizationScope(
            String requestUserId,
            String organizationId,
            String tenantId,
            String retrievalPurpose,
            Set<String> allowedDocumentTypes) {

        private AuthorizationScope {
            allowedDocumentTypes = allowedDocumentTypes == null ? Set.of() : Set.copyOf(allowedDocumentTypes);
            retrievalPurpose = retrievalPurpose == null ? "general_context" : retrievalPurpose;
        }
    }
}
