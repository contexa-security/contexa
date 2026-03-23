package io.contexa.contexacore.autonomous.saas.mapper;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.PromptContextAuditPayload;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
        assertThat(payload.getExecutionId()).isEqualTo("exec-001");
        assertThat(payload.getRetrievalPurpose()).isEqualTo("THREAT_RUNTIME_CONTEXT");
        assertThat(payload.getRequestedDocumentCount()).isEqualTo(3);
        assertThat(payload.getAllowedDocumentCount()).isEqualTo(1);
        assertThat(payload.getDeniedDocumentCount()).isEqualTo(2);
        assertThat(payload.getDeniedReasons()).containsExactly("purpose_mismatch", "quarantined_artifact");
        assertThat(payload.getAuditId()).isNotBlank();
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
}