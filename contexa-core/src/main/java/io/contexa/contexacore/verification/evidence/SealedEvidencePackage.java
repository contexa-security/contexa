package io.contexa.contexacore.verification.evidence;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * Immutable sealed evidence package capturing all inputs and outputs
 * of a Zero Trust security decision at the moment of enforcement.
 * Once persisted with a packageHash, this record must not be modified.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SealedEvidencePackage {

    public static final String SEAL_STATE_SEALED = "SEALED";

    private Long id;

    private String packageId;

    private String correlationId;

    private String tenantId;

    private String userId;

    private Instant capturedAt;

    // Section 1: HTTP request facts
    private String requestFactsJson;

    // Section 2: Authentication state
    private String authStateJson;

    // Section 3: Full CanonicalSecurityContext (12 sections)
    private String canonicalContextJson;

    // Section 4: Behavioral baseline snapshot
    private String baselineSnapshotJson;

    // Section 5: RAG retrieval results
    private String ragResultsJson;

    // Section 6: Assembled prompts (both raw and LLM-view)
    // Raw prompts: before compression/budget enforcement
    private String rawSystemPrompt;

    private String rawUserPrompt;

    // LLM-view prompts: after compression/budget enforcement (what LLM actually received)
    private String systemPromptText;

    private String userPromptText;

    private String promptHash;

    private String systemPromptHash;

    private String userPromptHash;

    private String rawSystemPromptHash;

    private String rawUserPromptHash;

    // Prompt execution metadata serialized
    private String promptExecutionMetadataJson;

    private String promptEvidenceManifestJson;

    @Builder.Default
    private String sealState = SEAL_STATE_SEALED;

    private String sealFailureReason;

    // Section 7: Decision result
    private String decisionJson;

    // Section 8: Integrity
    private String packageHash;

    @Builder.Default
    private int schemaVersion = 2;

    @Builder.Default
    private boolean sealed = true;

    private Instant expiresAt;

    private Instant createdAt;

    public boolean hasSealedState() {
        return SEAL_STATE_SEALED.equalsIgnoreCase(sealState);
    }
}
