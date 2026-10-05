package io.contexa.showcase.workload.contexa.template;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The learned engine state of one template principal, read through the engine's public stores (ADR-23). The portal
 * keeps it in {@code engine_template} and hands it back for every run, which writes it under the run's own keys.
 *
 * @param userBaseline          the user's behaviour baseline as JSON (BaselineVector), or null
 * @param organizationBaseline  the template organization's baseline as JSON, or null
 * @param workProfileObservations work-profile observations, oldest first
 * @param authorizationState    stored authorization scope state of the user
 * @param scopeKey              role-scope key; identical for every principal with the same authorities
 * @param roleScopeObservations role-scope observations of that key, oldest first
 * @param permissionChangeObservations permission change observations of the user, oldest first
 * @param behaviourDocuments    the user's behaviour memory documents (content, metadata and stored embedding)
 */
public record TemplateSnapshot(
        String templateUser,
        String employeeKey,
        String organizationId,
        String tenantId,
        long baselineUpdateCount,
        String userBaseline,
        String organizationBaseline,
        List<String> workProfileObservations,
        String authorizationState,
        String scopeKey,
        List<String> roleScopeObservations,
        List<String> permissionChangeObservations,
        List<MemoryDocument> behaviourDocuments,
        Instant capturedAt) {

    /**
     * @param embedding the stored embedding in pgvector text form, or null for a snapshot taken before embeddings
     *                  were kept; a copy then keeps the embedding the vector service computes again
     */
    public record MemoryDocument(String content, Map<String, Object> metadata, String embedding) {
    }
}
