package io.contexa.showcase.workload.contexa.template;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.context.collector.RoleScopeCollector;
import io.contexa.contexacore.autonomous.context.collector.StoredRoleScopeHistory;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.showcase.workload.contexa.template.TemplateSnapshot.MemoryDocument;
import org.springframework.ai.document.Document;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Reads a template principal's learned state through the engine's public stores and writes it under a run
 * principal's keys (docs/showcase/ADR.md ADR-23). Behaviour memory documents are listed from the vector table
 * (the engine has no public listing) and copied into it with the template's stored embedding, so every clone ranks
 * the documents exactly like the template (P1-BE-09 T6) and a clone costs no embedding call (P4-BE-01: the calls made
 * a clone take seconds under concurrent runs). The copied metadata already holds the fields the engine's vector service
 * adds; a document without a stored embedding still goes through that service.
 * Decision, MFA and session state are never copied: a run principal starts as PENDING_ANALYSIS.
 */
public class TemplateSnapshots {

    static final int WORK_PROFILE_LIMIT = 5_000;
    static final int PERMISSION_CHANGE_LIMIT = 200;

    /** Metadata keys that hold the owner or scope of a memory document; a copy gets the run's values. */
    static final List<String> USER_KEYS = List.of("userId");
    static final List<String> ORGANIZATION_KEYS = List.of("organizationId", "organization_id", "orgId");
    static final List<String> TENANT_KEYS = List.of("tenantId", "tenant_id");
    static final List<String> IDENTITY_KEYS = List.of("id", "artifactId", "eventId");

    private static final TypeReference<Map<String, Object>> METADATA = new TypeReference<>() {
    };

    private final BaselineDataStore baselines;
    private final SecurityContextDataStore contexts;
    private final RoleScopeCollector roleScopes;
    private final UnifiedVectorService vectors;
    private final JdbcTemplate vectorDatabase;
    private final ObjectMapper json;
    private final Clock clock;

    public TemplateSnapshots(BaselineDataStore baselines, SecurityContextDataStore contexts,
                             RoleScopeCollector roleScopes, UnifiedVectorService vectors, JdbcTemplate vectorDatabase,
                             ObjectMapper json, Clock clock) {
        this.baselines = baselines;
        this.contexts = contexts;
        this.roleScopes = roleScopes;
        this.vectors = vectors;
        this.vectorDatabase = vectorDatabase;
        this.json = json;
        this.clock = clock;
    }

    public TemplateSnapshot export(String templateUser, String employeeKey, String organizationId, String tenantId) {
        BaselineVector user = baselines.getUserBaseline(templateUser);
        BaselineVector organization = baselines.getOrganizationBaseline(organizationId);
        StoredRoleScopeHistory roleScope = roleScopes.inspectStoredHistory(tenantId, templateUser);
        List<MemoryDocument> documents = vectorDatabase.query("""
                        select content, metadata::text, embedding::text from vector_store
                         where metadata::jsonb ->> 'userId' = ? and metadata::jsonb ->> 'documentType' = 'behavior'
                         order by metadata::jsonb ->> 'timestamp', id""",
                (rs, n) -> new MemoryDocument(rs.getString(1), readMetadata(rs.getString(2)), rs.getString(3)),
                templateUser);
        return new TemplateSnapshot(templateUser, employeeKey, organizationId, tenantId,
                user == null || user.getUpdateCount() == null ? 0 : user.getUpdateCount(),
                write(user), write(organization),
                contexts.getRecentWorkProfileObservations(tenantId, templateUser, WORK_PROFILE_LIMIT),
                roleScope.authorizationState(), roleScope.scopeKey(), roleScope.observations(),
                contexts.getRecentPermissionChangeObservations(tenantId, templateUser, PERMISSION_CHANGE_LIMIT),
                documents, clock.instant());
    }

    /** Writes the snapshot under the run principal, organization and tenant. Returns the number of documents. */
    public int importInto(TemplateSnapshot snapshot, String runUser, String organizationId, String tenantId) {
        if (snapshot.userBaseline() != null) {
            BaselineVector user = read(snapshot.userBaseline());
            user.setUserId(runUser);
            baselines.saveUserBaseline(runUser, user);
        }
        if (snapshot.organizationBaseline() != null) {
            BaselineVector organization = read(snapshot.organizationBaseline());
            organization.setUserId("org:" + organizationId);
            baselines.saveOrganizationBaseline(organizationId, organization);
        }
        snapshot.workProfileObservations().forEach(observation ->
                contexts.addWorkProfileObservation(tenantId, runUser, observation));
        if (snapshot.scopeKey() != null) {
            snapshot.roleScopeObservations().forEach(observation ->
                    contexts.addRoleScopeObservation(tenantId, snapshot.scopeKey(), observation));
        }
        snapshot.permissionChangeObservations().forEach(observation ->
                contexts.addPermissionChangeObservation(tenantId, runUser, observation));
        if (snapshot.authorizationState() != null) {
            contexts.setAuthorizationScopeState(tenantId, runUser, snapshot.authorizationState());
        }
        List<MemoryDocument> sources = snapshot.behaviourDocuments();
        List<Document> documents = sources.stream()
                .map(document -> copy(document, runUser, organizationId, tenantId))
                .toList();
        List<Document> withoutEmbedding = new ArrayList<>();
        for (int i = 0; i < documents.size(); i++) {
            Document document = documents.get(i);
            String embedding = sources.get(i).embedding();
            if (embedding == null) {
                withoutEmbedding.add(document);
                continue;
            }
            // Metadata goes through jsonb exactly as the vector store writes it, so the keys keep the stored order.
            vectorDatabase.update("""
                            insert into vector_store (id, content, metadata, embedding)
                            values (cast(? as uuid), ?, cast(? as jsonb), cast(? as vector))""",
                    document.getId(), document.getText(), writeMetadata(document.getMetadata()), embedding);
        }
        if (!withoutEmbedding.isEmpty()) {
            vectors.storeDocuments(withoutEmbedding);
        }
        return documents.size();
    }

    static Document copy(MemoryDocument document, String runUser, String organizationId, String tenantId) {
        Map<String, Object> metadata = new LinkedHashMap<>(document.metadata());
        String id = UUID.randomUUID().toString();
        replacePresent(metadata, USER_KEYS, runUser);
        replacePresent(metadata, ORGANIZATION_KEYS, organizationId);
        replacePresent(metadata, TENANT_KEYS, tenantId);
        replacePresent(metadata, IDENTITY_KEYS, id);
        return new Document(id, document.content(), metadata);
    }

    private static void replacePresent(Map<String, Object> metadata, List<String> keys, String value) {
        for (String key : keys) {
            if (metadata.containsKey(key)) {
                metadata.put(key, value);
            }
        }
    }

    private Map<String, Object> readMetadata(String text) {
        try {
            return json.readValue(text, METADATA);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unreadable vector metadata", e);
        }
    }

    private String writeMetadata(Map<String, Object> metadata) {
        try {
            return json.writeValueAsString(metadata);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unwritable vector metadata", e);
        }
    }

    private String write(BaselineVector baseline) {
        if (baseline == null) {
            return null;
        }
        try {
            return json.writeValueAsString(baseline);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unwritable baseline", e);
        }
    }

    private BaselineVector read(String text) {
        try {
            return json.readValue(text, BaselineVector.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unreadable baseline in the template snapshot", e);
        }
    }
}
