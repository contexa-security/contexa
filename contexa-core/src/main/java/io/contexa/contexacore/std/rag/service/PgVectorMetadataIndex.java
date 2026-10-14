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

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.regex.Pattern;

/**
 * The metadata index of the pgvector table (W2-15): a GIN index on the metadata as jsonb with {@code jsonb_path_ops},
 * the operator class of the {@code @@ jsonpath} test the Spring AI filter writes. With it the planner reads one
 * user's rows directly, so a personal search is exact and quick; without it the exact search reads the whole table.
 * It is built concurrently, so that writers are not held while it is built on a large table.
 */
@Slf4j
public final class PgVectorMetadataIndex {

    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}");

    private PgVectorMetadataIndex() {
    }

    /** Creates the index when it does not exist. The schema and table must be plain identifiers. */
    public static void ensure(JdbcTemplate jdbcTemplate, String schema, String table) {
        String schemaName = identifier(schema);
        String tableName = identifier(table);
        jdbcTemplate.execute("CREATE INDEX CONCURRENTLY IF NOT EXISTS " + tableName + "_metadata_path_idx ON "
                + schemaName + "." + tableName + " USING gin ((metadata::jsonb) jsonb_path_ops)");
    }

    /** Creates the index for a pgvector store; any other store has none. A failure is logged and the store works on. */
    public static void ensureFor(VectorStore vectorStore, String schema, String table) {
        JdbcTemplate jdbcTemplate = PgVectorSearchSettings.pgVectorJdbcTemplate(vectorStore);
        if (jdbcTemplate == null) {
            return;
        }
        try {
            ensure(jdbcTemplate, schema, table);
        } catch (RuntimeException e) {
            log.error("[PgVectorMetadataIndex] Metadata index could not be created on {}.{}; personal searches read the whole table",
                    schema, table, e);
        }
    }

    private static String identifier(String name) {
        if (name == null || !IDENTIFIER.matcher(name).matches()) {
            throw new IllegalArgumentException("Not a plain SQL identifier: " + name);
        }
        return name;
    }
}
