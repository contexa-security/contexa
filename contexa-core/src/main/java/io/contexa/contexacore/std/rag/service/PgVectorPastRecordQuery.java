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
package io.contexa.contexacore.std.rag.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.autonomous.context.support.PastDeniedDecisions;
import io.contexa.contexacore.autonomous.context.support.PastRecordGroup;
import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.context.support.PastRecordScope;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The exact past record lookup on the pgvector table (W3-18): a containment test on the metadata (the GIN index of the
 * metadata, W2-15, answers it) and plain conditions on the session and the learning state, with no embedding call.
 * Records are shown in a fixed order: those of the first paths, then the latest time, then the stored ID.
 */
public class PgVectorPastRecordQuery implements PastRecordQuery {

    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}");
    private static final TypeReference<Map<String, Object>> METADATA = new TypeReference<>() {
    };

    private final JdbcTemplate jdbcTemplate;
    private final String table;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public PgVectorPastRecordQuery(VectorStore vectorStore, String schema, String table) {
        this.jdbcTemplate = PgVectorSearchSettings.pgVectorJdbcTemplate(vectorStore);
        this.table = identifier(schema) + "." + identifier(table);
    }

    @Override
    public boolean available() {
        return jdbcTemplate != null;
    }

    @Override
    public List<PastRecordGroup> groups(PastRecordScope scope) {
        if (jdbcTemplate == null) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select metadata::jsonb ->> 'pathFamily' as path_family,
                               metadata::jsonb ->> 'requestPath' as request_path,
                               metadata::jsonb ->> 'httpMethod' as http_method,
                               count(*) as records,
                               max(metadata::jsonb ->> 'timestamp') as latest
                          from %s
                         where %s
                         group by 1, 2, 3
                        """.formatted(table, SCOPE_CONDITION),
                (rs, rowNum) -> new PastRecordGroup(rs.getString("path_family"), rs.getString("request_path"),
                        rs.getString("http_method"), rs.getLong("records"), time(rs.getString("latest"))),
                scopeArguments(scope, containment(scope)).toArray());
    }

    @Override
    public List<Document> records(PastRecordScope scope, List<String> firstPaths, int limit) {
        if (jdbcTemplate == null || limit <= 0) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select id::text as id, content, metadata::text as metadata
                          from %s
                         where %s
                         order by case when coalesce(metadata::jsonb ->> 'requestPath', '')
                                            in (select jsonb_array_elements_text(cast(? as jsonb))) then 0 else 1 end,
                                  metadata::jsonb ->> 'timestamp' desc nulls last,
                                  id::text
                         limit ?
                        """.formatted(table, SCOPE_CONDITION),
                (rs, rowNum) -> new Document(rs.getString("id"), rs.getString("content"), metadata(rs.getString("metadata"))),
                withTail(scopeArguments(scope, containment(scope)), json(firstPaths != null ? firstPaths : List.of()),
                        limit).toArray());
    }

    @Override
    public List<String> filters() {
        return FILTERS;
    }

    @Override
    public List<String> order() {
        return ORDER;
    }

    @Override
    public List<Document> deniedDecisions(PastRecordScope scope, LocalDateTime since, int limit) {
        if (jdbcTemplate == null || scope == null || limit <= 0) {
            return List.of();
        }
        Map<String, Object> containment = new LinkedHashMap<>();
        containment.put(VectorDocumentMetadata.USER_ID, scope.userId());
        if (StringUtils.hasText(scope.retrievalPurpose())) {
            containment.put(VectorDocumentMetadata.RETRIEVAL_PURPOSE, scope.retrievalPurpose());
        }
        containment.put("actionFamily", scope.actionFamily());
        if (StringUtils.hasText(scope.agentId())) {
            containment.put(LearningSubject.AGENT_ID, scope.agentId());
        }
        String sql = "select id::text as id, content, metadata::text as metadata from " + table
                + " where " + SCOPE_CONDITION
                + " and metadata::jsonb ->> 'documentType' in (select jsonb_array_elements_text(cast(? as jsonb)))"
                + " and coalesce(metadata::jsonb ->> 'timestamp', '') >= ?"
                + " order by metadata::jsonb ->> 'timestamp' desc nulls last, id::text limit ?";
        return jdbcTemplate.query(sql,
                (rs, rowNum) -> new Document(rs.getString("id"), rs.getString("content"), metadata(rs.getString("metadata"))),
                withTail(scopeArguments(scope, json(containment)), json(PastDeniedDecisions.DOCUMENT_TYPES),
                        since != null ? since.toString() : "", limit).toArray());
    }

    @Override
    public boolean recordOutcome(String documentId, String outcome) {
        if (jdbcTemplate == null || !StringUtils.hasText(documentId) || !StringUtils.hasText(outcome)) {
            return false;
        }
        String sql = "update " + table + " set metadata = (metadata::jsonb || jsonb_build_object('"
                + PastDeniedDecisions.OUTCOME_KEY + "', cast(? as text)))::json where id::text = ?";
        return jdbcTemplate.update(sql, outcome, documentId) > 0;
    }

    @Override
    public int quarantineAgentRecords(String agentId, String delegationId) {
        if (jdbcTemplate == null || !StringUtils.hasText(agentId)) {
            return 0;
        }
        // The learning state the record had is kept, so that a release gives it back (a held record stays held).
        return jdbcTemplate.update("update " + table + " set metadata = (metadata::jsonb || jsonb_build_object("
                + "'" + VectorDocumentMetadata.LEARNING_STATE + "', cast(? as text), '" + STATE_BEFORE_QUARANTINE
                + "', coalesce(metadata::jsonb ->> '" + VectorDocumentMetadata.LEARNING_STATE + "', '')))::json"
                + " where metadata::jsonb @> cast(? as jsonb)"
                + " and coalesce(metadata::jsonb ->> '" + VectorDocumentMetadata.LEARNING_STATE + "', '') <> ?",
                VectorDocumentMetadata.LEARNING_STATE_QUARANTINED, agentContainment(agentId, delegationId),
                VectorDocumentMetadata.LEARNING_STATE_QUARANTINED);
    }

    @Override
    public int releaseAgentRecords(String agentId, String delegationId, Collection<String> quarantinedDelegations) {
        if (jdbcTemplate == null || !StringUtils.hasText(agentId)) {
            return 0;
        }
        List<String> kept = quarantinedDelegations != null ? List.copyOf(quarantinedDelegations) : List.of();
        return jdbcTemplate.update("update " + table + " set metadata = (case when coalesce(metadata::jsonb ->> '"
                + STATE_BEFORE_QUARANTINE + "', '') = '' then metadata::jsonb - '" + VectorDocumentMetadata.LEARNING_STATE
                + "' else metadata::jsonb || jsonb_build_object('" + VectorDocumentMetadata.LEARNING_STATE
                + "', metadata::jsonb ->> '" + STATE_BEFORE_QUARANTINE + "') end - '" + STATE_BEFORE_QUARANTINE + "')::json"
                + " where metadata::jsonb @> cast(? as jsonb)"
                + " and coalesce(metadata::jsonb ->> '" + VectorDocumentMetadata.LEARNING_STATE + "', '') = ?"
                + " and coalesce(metadata::jsonb ->> '" + LearningSubject.DELEGATION_ID + "', '') not in"
                + " (select jsonb_array_elements_text(cast(? as jsonb)))",
                agentContainment(agentId, delegationId), VectorDocumentMetadata.LEARNING_STATE_QUARANTINED, json(kept));
    }

    @Override
    public int removeAgentRecords(String agentId, String delegationId) {
        if (jdbcTemplate == null || !StringUtils.hasText(agentId)) {
            return 0;
        }
        return jdbcTemplate.update("delete from " + table + " where metadata::jsonb @> cast(? as jsonb)",
                agentContainment(agentId, delegationId));
    }

    private String agentContainment(String agentId, String delegationId) {
        Map<String, Object> containment = new LinkedHashMap<>();
        containment.put(LearningSubject.AGENT_ID, agentId.trim());
        if (StringUtils.hasText(delegationId)) {
            containment.put(LearningSubject.DELEGATION_ID, delegationId.trim());
        }
        return json(containment);
    }

    /** docs/agent A3-8: the learning state a quarantined record had, for its release. */
    private static final String STATE_BEFORE_QUARANTINE = "learningStateBeforeQuarantine";

    /** W6-12: the conditions of SCOPE_CONDITION and containment(), in words for the seal; they change with that SQL. */
    private static final List<String> FILTERS = List.of(
            "documentType == behavior",
            "userId == scope.userId",
            "retrievalPurpose == scope.retrievalPurpose (when set)",
            "actionFamily == scope.actionFamily",
            "sessionId not in scope.excludedSessionIds",
            "learningState not in (" + VectorDocumentMetadata.LEARNING_STATE_HELD + ", "
                    + VectorDocumentMetadata.LEARNING_STATE_QUARANTINED + ")",
            "agentId == scope.agentId, or no agentId for a person's request",
            "tenantId == scope.tenantId when the record has one, else organizationId == scope.organizationId when the"
                    + " record has one");
    /** W6-12: the order keys of records(), in words for the seal; they change with that SQL. */
    private static final List<String> ORDER = List.of(
            "requestPath in firstPaths first",
            "timestamp desc nulls last",
            "id");

    /** The record's tenant as the document authorization reads it (PromptContextAuthorizationService). */
    private static final String TENANT = "coalesce(metadata::jsonb ->> 'tenantId', metadata::jsonb ->> 'tenant_id', '')";
    private static final String ORGANIZATION =
            "coalesce(metadata::jsonb ->> 'organizationId', metadata::jsonb ->> 'organization_id', '')";

    /**
     * The scope: the user's records of the purpose and action family (and agent), outside the session, neither held
     * back nor quarantined, of the request's subject and tenant (A3-1, A3-2). The tenant condition is the document
     * authorization's: a record bound to no tenant or organization is read; a record of a tenant is read by a request
     * of that tenant; a record of an organization alone by a request of that organization.
     */
    private static final String SCOPE_CONDITION = """
            metadata::jsonb @> cast(? as jsonb)
                           and coalesce(metadata::jsonb ->> 'sessionId', '')
                               not in (select jsonb_array_elements_text(cast(? as jsonb)))
                           and coalesce(metadata::jsonb ->> 'learningState', '') not in (?, ?)
                           and (cast(? as text) is not null or not jsonb_exists(metadata::jsonb, 'agentId'))
                           and ((%1$s = '' and %2$s = '')
                                or (%1$s <> '' and lower(%1$s) = lower(coalesce(cast(? as text), '')))
                                or (not (%1$s <> '' and cast(? as text) is not null) and %2$s <> ''
                                    and lower(%2$s) = lower(coalesce(cast(? as text), ''))))""".formatted(TENANT, ORGANIZATION);

    private String containment(PastRecordScope scope) {
        Map<String, Object> containment = new LinkedHashMap<>();
        containment.put("documentType", VectorDocumentType.BEHAVIOR.getValue());
        containment.put(VectorDocumentMetadata.USER_ID, scope.userId());
        if (StringUtils.hasText(scope.retrievalPurpose())) {
            containment.put(VectorDocumentMetadata.RETRIEVAL_PURPOSE, scope.retrievalPurpose());
        }
        containment.put("actionFamily", scope.actionFamily());
        if (StringUtils.hasText(scope.agentId())) {
            containment.put(LearningSubject.AGENT_ID, scope.agentId());
        }
        return json(containment);
    }

    /** The arguments of {@link #SCOPE_CONDITION} in its order, after the containment. */
    private List<Object> scopeArguments(PastRecordScope scope, String containment) {
        List<Object> arguments = new ArrayList<>();
        arguments.add(containment);
        arguments.add(json(scope.excludedSessionIds()));
        arguments.add(VectorDocumentMetadata.LEARNING_STATE_HELD);
        arguments.add(VectorDocumentMetadata.LEARNING_STATE_QUARANTINED);
        arguments.add(text(scope.agentId()));
        arguments.add(text(scope.tenantId()));
        arguments.add(text(scope.tenantId()));
        arguments.add(text(scope.organizationId()));
        return arguments;
    }

    private static List<Object> withTail(List<Object> arguments, Object... tail) {
        List<Object> all = new ArrayList<>(arguments);
        all.addAll(Arrays.asList(tail));
        return all;
    }

    private static String text(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        }
        catch (JsonProcessingException exception) {
            throw new IllegalStateException("A past record lookup value could not be written as JSON", exception);
        }
    }

    private Map<String, Object> metadata(String json) {
        if (!StringUtils.hasText(json)) {
            return new LinkedHashMap<>();
        }
        try {
            return objectMapper.readValue(json, METADATA);
        }
        catch (JsonProcessingException exception) {
            throw new IllegalStateException("The metadata of a past record could not be read", exception);
        }
    }

    private static LocalDateTime time(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        try {
            return LocalDateTime.parse(value.trim());
        }
        catch (DateTimeParseException exception) {
            return null;
        }
    }

    private static String identifier(String name) {
        if (name == null || !IDENTIFIER.matcher(name).matches()) {
            throw new IllegalArgumentException("Not a plain SQL identifier: " + name);
        }
        return name;
    }
}
