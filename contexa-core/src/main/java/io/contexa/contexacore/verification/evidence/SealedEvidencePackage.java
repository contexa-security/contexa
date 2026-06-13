package io.contexa.contexacore.verification.evidence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

/**
 * Immutable sealed evidence package capturing all inputs and outputs
 * of a Zero Trust security decision at the moment of enforcement.
 * Once persisted with a packageHash, this record must not be modified.
 */
@Entity
@Table(name = "sealed_evidence_package", indexes = {
        @Index(name = "idx_sep_correlation_id", columnList = "correlation_id", unique = true),
        @Index(name = "idx_sep_user_id_captured_at", columnList = "user_id, captured_at"),
        @Index(name = "idx_sep_tenant_id_captured_at", columnList = "tenant_id, captured_at"),
        @Index(name = "idx_sep_captured_at", columnList = "captured_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class SealedEvidencePackage {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "package_id", nullable = false, unique = true, length = 256)
    private String packageId;

    @Column(name = "correlation_id", nullable = false, length = 160)
    private String correlationId;

    @Column(name = "tenant_id", length = 120)
    private String tenantId;

    @Column(name = "user_id", length = 160)
    private String userId;

    @Column(name = "captured_at", nullable = false)
    private Instant capturedAt;

    // Section 1: HTTP request facts
    @Column(name = "request_facts_json", columnDefinition = "TEXT")
    private String requestFactsJson;

    // Section 2: Authentication state
    @Column(name = "auth_state_json", columnDefinition = "TEXT")
    private String authStateJson;

    // Section 3: Full CanonicalSecurityContext (12 sections)
    @Column(name = "canonical_context_json", columnDefinition = "TEXT")
    private String canonicalContextJson;

    // Section 4: Behavioral baseline snapshot
    @Column(name = "baseline_snapshot_json", columnDefinition = "TEXT")
    private String baselineSnapshotJson;

    // Section 5: RAG retrieval results
    @Column(name = "rag_results_json", columnDefinition = "TEXT")
    private String ragResultsJson;

    // Section 6: Assembled prompts (both raw and LLM-view)
    // Raw prompts: before compression/budget enforcement
    @Column(name = "raw_system_prompt", columnDefinition = "TEXT")
    private String rawSystemPrompt;

    @Column(name = "raw_user_prompt", columnDefinition = "TEXT")
    private String rawUserPrompt;

    // LLM-view prompts: after compression/budget enforcement (what LLM actually received)
    @Column(name = "system_prompt_text", columnDefinition = "TEXT")
    private String systemPromptText;

    @Column(name = "user_prompt_text", columnDefinition = "TEXT")
    private String userPromptText;

    @Column(name = "prompt_hash", length = 128)
    private String promptHash;

    @Column(name = "system_prompt_hash", length = 128)
    private String systemPromptHash;

    @Column(name = "user_prompt_hash", length = 128)
    private String userPromptHash;

    @Column(name = "raw_system_prompt_hash", length = 128)
    private String rawSystemPromptHash;

    @Column(name = "raw_user_prompt_hash", length = 128)
    private String rawUserPromptHash;

    // Prompt execution metadata serialized
    @Column(name = "prompt_execution_metadata_json", columnDefinition = "TEXT")
    private String promptExecutionMetadataJson;

    @Column(name = "prompt_evidence_manifest_json", columnDefinition = "TEXT")
    private String promptEvidenceManifestJson;

    @Column(name = "seal_state", nullable = false, length = 32)
    @Builder.Default
    private String sealState = "SEALED";

    @Column(name = "seal_failure_reason", columnDefinition = "TEXT")
    private String sealFailureReason;

    // Section 7: Decision result
    @Column(name = "decision_json", columnDefinition = "TEXT")
    private String decisionJson;

    // Section 8: Integrity
    @Column(name = "package_hash", nullable = false, length = 128)
    private String packageHash;

    @Column(name = "schema_version", nullable = false)
    @Builder.Default
    private int schemaVersion = 2;

    @Column(name = "sealed", nullable = false)
    @Builder.Default
    private boolean sealed = true;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @PreUpdate
    protected void onPreUpdate() {
        if (this.sealed) {
            throw new IllegalStateException("Sealed evidence package cannot be modified after persistence");
        }
    }
}
