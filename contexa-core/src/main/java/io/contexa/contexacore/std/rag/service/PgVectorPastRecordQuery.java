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
                containment(scope), json(scope.excludedSessionIds()), VectorDocumentMetadata.LEARNING_STATE_HELD);
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
                containment(scope), json(scope.excludedSessionIds()), VectorDocumentMetadata.LEARNING_STATE_HELD,
                json(firstPaths != null ? firstPaths : List.of()), limit);
    }

    /** The scope: the user's behaviour records of the purpose and action family, outside the session, not held back. */
    private static final String SCOPE_CONDITION = """
            metadata::jsonb @> cast(? as jsonb)
                           and coalesce(metadata::jsonb ->> 'sessionId', '')
                               not in (select jsonb_array_elements_text(cast(? as jsonb)))
                           and coalesce(metadata::jsonb ->> 'learningState', '') <> ?""";

    private String containment(PastRecordScope scope) {
        Map<String, Object> containment = new LinkedHashMap<>();
        containment.put("documentType", VectorDocumentType.BEHAVIOR.getValue());
        containment.put(VectorDocumentMetadata.USER_ID, scope.userId());
        if (StringUtils.hasText(scope.retrievalPurpose())) {
            containment.put(VectorDocumentMetadata.RETRIEVAL_PURPOSE, scope.retrievalPurpose());
        }
        containment.put("actionFamily", scope.actionFamily());
        return json(containment);
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
