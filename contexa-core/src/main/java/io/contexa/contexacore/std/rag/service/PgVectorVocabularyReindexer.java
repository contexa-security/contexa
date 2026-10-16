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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.support.VocabularyMigration;
import io.contexa.contexacore.autonomous.context.support.VocabularyVersion;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Moves the past-record documents of another classification vocabulary into today's (W5-7 D5): the metadata of every
 * behaviour or decision document whose version is not today's is read through {@link VocabularyMigration} and written
 * back under the same ID. The content and the embedding stay as they are.
 */
public class PgVectorVocabularyReindexer {

    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}");
    private static final TypeReference<Map<String, Object>> METADATA = new TypeReference<>() {
    };
    private static final List<String> DOCUMENT_TYPES = List.of("behavior", "suspicious", "threat", "ambiguous");

    private final JdbcTemplate jdbcTemplate;
    private final String table;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public PgVectorVocabularyReindexer(VectorStore vectorStore, String schema, String table) {
        this.jdbcTemplate = PgVectorSearchSettings.pgVectorJdbcTemplate(vectorStore);
        this.table = identifier(schema) + "." + identifier(table);
    }

    /** Rewrites the documents of another vocabulary batch by batch; the number rewritten. */
    public int reindex(int batchSize) {
        if (jdbcTemplate == null || batchSize <= 0) {
            return 0;
        }
        String select = "select id::text as id, metadata::text as metadata from " + table
                + " where coalesce(metadata::jsonb ->> 'vocabularyVersion', '') <> ?"
                + " and metadata::jsonb ->> 'documentType' in (select jsonb_array_elements_text(cast(? as jsonb)))"
                + " order by id::text limit ?";
        String update = "update " + table + " set metadata = cast(? as json) where id::text = ?";
        int rewritten = 0;
        while (true) {
            List<Map.Entry<String, String>> batch = jdbcTemplate.query(select,
                    (rs, rowNum) -> Map.entry(rs.getString("id"), rs.getString("metadata")),
                    VocabularyVersion.CURRENT, json(DOCUMENT_TYPES), batchSize);
            if (batch.isEmpty()) {
                return rewritten;
            }
            for (Map.Entry<String, String> document : batch) {
                Map<String, Object> migrated = VocabularyMigration.pastRecordMetadata(read(document.getValue()));
                jdbcTemplate.update(update, json(migrated), document.getKey());
                rewritten++;
            }
        }
    }

    private Map<String, Object> read(String metadata) {
        try {
            return objectMapper.readValue(metadata, METADATA);
        } catch (Exception e) {
            throw new IllegalStateException("Unreadable document metadata", e);
        }
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalStateException("Unwritable document metadata", e);
        }
    }

    private static String identifier(String value) {
        if (value == null || !IDENTIFIER.matcher(value).matches()) {
            throw new IllegalArgumentException("Not a plain SQL identifier: " + value);
        }
        return value;
    }
}
