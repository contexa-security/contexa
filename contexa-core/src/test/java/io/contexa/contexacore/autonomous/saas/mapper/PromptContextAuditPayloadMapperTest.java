package io.contexa.contexacore.autonomous.saas.mapper;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.PromptContextAuditPayload;
import io.contexa.contexacore.std.security.AuthorizedPromptContextItem;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PromptContextAuditPayloadMapperTest {

    private final PromptContextAuditPayloadMapper mapper = new PromptContextAuditPayloadMapper();

    @Test
    void mapBuildsAuditPayloadFromAuthorizedPromptContext() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-001")
                .timestamp(LocalDateTime.of(2026, 3, 19, 10, 0))
                .metadata(Map.of(
                        "tenantId", "tenant-acme",
                        "correlationId", "corr-001",
                        "executionId", "exec-001"))
                .build();
        AuthorizedPromptContext authorizedPromptContext = new AuthorizedPromptContext(
                List.of(new Document("threat context", new LinkedHashMap<>(Map.ofEntries(
                        Map.entry(VectorDocumentMetadata.SOURCE_TYPE, "knowledge_artifact"),
                        Map.entry(VectorDocumentMetadata.ARTIFACT_ID, "artifact-1"),
                        Map.entry(VectorDocumentMetadata.ARTIFACT_VERSION, "v1"),
                        Map.entry(VectorDocumentMetadata.AUTHORIZATION_DECISION, "ALLOW"),
                        Map.entry(VectorDocumentMetadata.PURPOSE_MATCH, true),
                        Map.entry(VectorDocumentMetadata.PROVENANCE_SUMMARY, "case memory"),
                        Map.entry(VectorDocumentMetadata.PROMPT_SAFETY_DECISION, "ALLOW"),
                        Map.entry(VectorDocumentMetadata.MEMORY_READ_DECISION, "ALLOW"),
                        Map.entry(VectorDocumentMetadata.ACCESS_SCOPE, "TENANT"),
                        Map.entry(VectorDocumentMetadata.TENANT_BOUND, true),
                        Map.entry(VectorDocumentMetadata.SIMILARITY_SCORE, 0.84))))),
                3,
                1,
                2,
                "THREAT_RUNTIME_CONTEXT",
                List.of("purpose_mismatch", "quarantined_artifact"));

        PromptContextAuditPayload payload = mapper.map(event, null, authorizedPromptContext);

        assertThat(payload.getCorrelationId()).isEqualTo("corr-001");
        assertThat(payload.getTenantExternalRef()).isEqualTo("tenant-acme");
        assertThat(payload.getExecutionId()).isEqualTo("exec-001");
        assertThat(payload.getRetrievalPurpose()).isEqualTo("THREAT_RUNTIME_CONTEXT");
        assertThat(payload.getRequestedDocumentCount()).isEqualTo(3);
        assertThat(payload.getAllowedDocumentCount()).isEqualTo(1);
        assertThat(payload.getDeniedDocumentCount()).isEqualTo(2);
        assertThat(payload.getDeniedReasons()).containsExactly("purpose_mismatch", "quarantined_artifact");
        assertThat(payload.getAuditId()).isNotBlank();
        assertThat(payload.getContextFingerprint()).isNotBlank();
        assertThat(payload.getContexts()).hasSize(1);
        assertThat(payload.getContexts().getFirst().getArtifactId()).isEqualTo("artifact-1");
        assertThat(payload.getContexts().getFirst().getAuthorizationDecision()).isEqualTo("ALLOW");
        assertThat(payload.getContexts().getFirst().isTenantBound()).isTrue();
        assertThat(payload.getContexts().getFirst().getSimilarityScore()).isEqualTo(0.84);
    }

    @Test
    void resolveTenantExternalRefFallsBackToOrganizationId() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-002")
                .metadata(Map.of("organizationId", "org-acme"))
                .build();

        assertThat(mapper.resolveTenantExternalRef(event)).isEqualTo("org-acme");
        assertThat(mapper.resolveTenantExternalRef(SecurityEvent.builder().eventId("evt-003").build())).isEqualTo("default");
    }

    @Test
    void mapIncludesAllowedAndDeniedContextItemsWithoutCollapsingThem() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-allowed-denied")
                .metadata(Map.of(
                        "tenantId", "tenant-acme",
                        "correlationId", "corr-allowed-denied"))
                .build();
        AuthorizedPromptContext authorizedPromptContext = new AuthorizedPromptContext(
                List.of(),
                2,
                1,
                1,
                "THREAT_RUNTIME_CONTEXT",
                List.of("DENIED_TENANT_SCOPE"),
                null,
                List.of(),
                List.of(
                        AuthorizedPromptContextItem.builder()
                                .contextType("THREAT_CASE")
                                .sourceType("knowledge_artifact")
                                .artifactId("artifact-allow")
                                .artifactVersion("v1")
                                .authorizationDecision("ALLOWED_TENANT_SCOPE")
                                .purposeMatch(true)
                                .provenanceSummary("allowed case memory")
                                .includedInPrompt(true)
                                .promptSafetyDecision("ALLOW")
                                .memoryReadDecision("ALLOW")
                                .accessScope("TENANT")
                                .tenantBound(true)
                                .similarityScore(0.91)
                                .build(),
                        AuthorizedPromptContextItem.builder()
                                .contextType("THREAT_CASE")
                                .sourceType("knowledge_artifact")
                                .artifactId("artifact-deny")
                                .artifactVersion("v1")
                                .authorizationDecision("DENIED_TENANT_SCOPE")
                                .purposeMatch(true)
                                .provenanceSummary("denied tenant scope")
                                .includedInPrompt(false)
                                .accessScope("TENANT")
                                .tenantBound(true)
                                .similarityScore(0.71)
                                .build()));

        PromptContextAuditPayload payload = mapper.map(event, null, authorizedPromptContext);

        assertThat(payload.getContexts()).hasSize(2);
        assertThat(payload.getContexts())
                .extracting(PromptContextAuditPayload.ContextItem::getArtifactId)
                .containsExactlyInAnyOrder("artifact-allow", "artifact-deny");
        assertThat(payload.getContexts())
                .filteredOn(PromptContextAuditPayload.ContextItem::isIncludedInPrompt)
                .singleElement()
                .extracting(PromptContextAuditPayload.ContextItem::getArtifactId)
                .isEqualTo("artifact-allow");
        assertThat(payload.getContexts())
                .filteredOn(item -> !item.isIncludedInPrompt())
                .singleElement()
                .satisfies(item -> assertThat(item.getAuthorizationDecision()).isEqualTo("DENIED_TENANT_SCOPE"));
    }

    @Test
    void mapUsesContextFingerprintInAuditId() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-fingerprint")
                .metadata(Map.of(
                        "tenantId", "tenant-acme",
                        "correlationId", "corr-fingerprint"))
                .build();

        PromptContextAuditPayload first = mapper.map(event, "THREAT_RUNTIME_CONTEXT", new AuthorizedPromptContext(
                List.of(),
                1,
                1,
                0,
                "THREAT_RUNTIME_CONTEXT",
                List.of(),
                null,
                List.of(),
                List.of(AuthorizedPromptContextItem.builder()
                        .contextType("THREAT_CASE")
                        .sourceType("knowledge_artifact")
                        .artifactId("artifact-a")
                        .authorizationDecision("ALLOWED_TENANT_SCOPE")
                        .purposeMatch(true)
                        .provenanceSummary("case-a")
                        .includedInPrompt(true)
                        .accessScope("TENANT")
                        .tenantBound(true)
                        .build())));
        PromptContextAuditPayload second = mapper.map(event, "THREAT_RUNTIME_CONTEXT", new AuthorizedPromptContext(
                List.of(),
                1,
                0,
                1,
                "THREAT_RUNTIME_CONTEXT",
                List.of("DENIED_PURPOSE"),
                null,
                List.of(),
                List.of(AuthorizedPromptContextItem.builder()
                        .contextType("THREAT_CASE")
                        .sourceType("knowledge_artifact")
                        .artifactId("artifact-b")
                        .authorizationDecision("DENIED_PURPOSE")
                        .purposeMatch(false)
                        .provenanceSummary("case-b")
                        .includedInPrompt(false)
                        .accessScope("TENANT")
                        .tenantBound(true)
                        .build())));

        assertThat(first.getContextFingerprint()).isNotEqualTo(second.getContextFingerprint());
        assertThat(first.getAuditId()).isNotEqualTo(second.getAuditId());
    }

    @Test
    void mapNormalizesDeniedReasonOrderForStableFingerprint() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-stable-fingerprint")
                .metadata(Map.of(
                        "tenantId", "tenant-acme",
                        "correlationId", "corr-stable-fingerprint"))
                .build();

        AuthorizedPromptContext firstContext = new AuthorizedPromptContext(
                List.of(),
                2,
                0,
                2,
                "THREAT_RUNTIME_CONTEXT",
                List.of("DENIED_TENANT_SCOPE", "DENIED_PURPOSE", "DENIED_TENANT_SCOPE"),
                null,
                List.of(),
                List.of(
                        AuthorizedPromptContextItem.builder()
                                .contextType("THREAT_CASE")
                                .sourceType("knowledge_artifact")
                                .artifactId("artifact-a")
                                .authorizationDecision("DENIED_PURPOSE")
                                .purposeMatch(false)
                                .provenanceSummary("case-a")
                                .includedInPrompt(false)
                                .accessScope("TENANT")
                                .tenantBound(true)
                                .build(),
                        AuthorizedPromptContextItem.builder()
                                .contextType("THREAT_CASE")
                                .sourceType("knowledge_artifact")
                                .artifactId("artifact-b")
                                .authorizationDecision("DENIED_TENANT_SCOPE")
                                .purposeMatch(true)
                                .provenanceSummary("case-b")
                                .includedInPrompt(false)
                                .accessScope("TENANT")
                                .tenantBound(true)
                                .build()));
        AuthorizedPromptContext secondContext = new AuthorizedPromptContext(
                List.of(),
                2,
                0,
                2,
                "THREAT_RUNTIME_CONTEXT",
                List.of("DENIED_PURPOSE", "DENIED_TENANT_SCOPE"),
                null,
                List.of(),
                List.of(
                        AuthorizedPromptContextItem.builder()
                                .contextType("THREAT_CASE")
                                .sourceType("knowledge_artifact")
                                .artifactId("artifact-b")
                                .authorizationDecision("DENIED_TENANT_SCOPE")
                                .purposeMatch(true)
                                .provenanceSummary("case-b")
                                .includedInPrompt(false)
                                .accessScope("TENANT")
                                .tenantBound(true)
                                .build(),
                        AuthorizedPromptContextItem.builder()
                                .contextType("THREAT_CASE")
                                .sourceType("knowledge_artifact")
                                .artifactId("artifact-a")
                                .authorizationDecision("DENIED_PURPOSE")
                                .purposeMatch(false)
                                .provenanceSummary("case-a")
                                .includedInPrompt(false)
                                .accessScope("TENANT")
                                .tenantBound(true)
                                .build()));

        PromptContextAuditPayload first = mapper.map(event, "THREAT_RUNTIME_CONTEXT", firstContext);
        PromptContextAuditPayload second = mapper.map(event, "THREAT_RUNTIME_CONTEXT", secondContext);

        assertThat(first.getDeniedReasons()).containsExactly("DENIED_PURPOSE", "DENIED_TENANT_SCOPE");
        assertThat(first.getContextFingerprint()).isEqualTo(second.getContextFingerprint());
        assertThat(first.getAuditId()).isEqualTo(second.getAuditId());
    }
}
