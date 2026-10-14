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

import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Runs a vector search with the pgvector settings it needs (W2-15). pgvector applies a filter after it walks an
 * approximate index, so a search scoped to one user reads exactly: index scans are off for its transaction and the
 * planner reads the user's rows, through the metadata index when there is one ({@link PgVectorMetadataIndex}). Other
 * searches walk the HNSW index with the configured candidate list ({@code hnsw.ef_search}) and, from pgvector 0.8.0,
 * keep walking in strict distance order until they have as many rows as asked ({@code hnsw.iterative_scan}). The
 * settings hold for one read-only transaction on the store's own connection; a store that is not pgvector searches as
 * it is.
 */
@Slf4j
public class PgVectorSearchSettings {

    private static final String PG_VECTOR_STORE = "org.springframework.ai.vectorstore.pgvector.PgVectorStore";
    private static final int[] ITERATIVE_SCAN_VERSION = {0, 8, 0};

    private final int efSearch;
    private final ConcurrentMap<DataSource, TransactionTemplate> transactions = new ConcurrentHashMap<>();
    private final ConcurrentMap<DataSource, Boolean> iterativeScan = new ConcurrentHashMap<>();

    public PgVectorSearchSettings(PgVectorStoreProperties properties) {
        PgVectorStoreProperties source = properties != null ? properties : new PgVectorStoreProperties();
        this.efSearch = source.getHnsw().getEfSearch();
    }

    public List<Document> search(VectorStore vectorStore, SearchRequest request) {
        JdbcTemplate jdbcTemplate = pgVectorJdbcTemplate(vectorStore);
        if (jdbcTemplate == null) {
            return vectorStore.similaritySearch(request);
        }
        DataSource dataSource = jdbcTemplate.getDataSource();
        boolean personal = VectorSearchScope.of(request.getFilterExpression()).personal();
        boolean iterative = !personal && iterativeScanSupported(jdbcTemplate, dataSource);
        return transactions.computeIfAbsent(dataSource, PgVectorSearchSettings::readOnlyTransaction).execute(status -> {
            if (personal) {
                jdbcTemplate.execute("SET LOCAL enable_indexscan = off");
            } else {
                jdbcTemplate.execute("SET LOCAL hnsw.ef_search = " + efSearch);
                if (iterative) {
                    jdbcTemplate.execute("SET LOCAL hnsw.iterative_scan = strict_order");
                }
            }
            return vectorStore.similaritySearch(request);
        });
    }

    /** The JDBC template of a pgvector store, the one it searches with; null for any other store. */
    static JdbcTemplate pgVectorJdbcTemplate(VectorStore vectorStore) {
        if (vectorStore == null || !isPgVectorStore(vectorStore.getClass())) {
            return null;
        }
        Object client = vectorStore.getNativeClient().orElse(null);
        return client instanceof JdbcTemplate jdbcTemplate && jdbcTemplate.getDataSource() != null ? jdbcTemplate : null;
    }

    private static boolean isPgVectorStore(Class<?> type) {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            if (PG_VECTOR_STORE.equals(current.getName())) {
                return true;
            }
        }
        return false;
    }

    private static TransactionTemplate readOnlyTransaction(DataSource dataSource) {
        TransactionTemplate template = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        template.setReadOnly(true);
        return template;
    }

    private boolean iterativeScanSupported(JdbcTemplate jdbcTemplate, DataSource dataSource) {
        return iterativeScan.computeIfAbsent(dataSource, ignored -> {
            try {
                List<String> versions = jdbcTemplate.queryForList(
                        "SELECT extversion FROM pg_extension WHERE extname = 'vector'", String.class);
                return !versions.isEmpty() && atLeast(versions.get(0), ITERATIVE_SCAN_VERSION);
            } catch (RuntimeException e) {
                log.error("[PgVectorSearchSettings] pgvector version could not be read; iterative index scans stay off", e);
                return false;
            }
        });
    }

    static boolean atLeast(String version, int[] minimum) {
        if (version == null) {
            return false;
        }
        String[] parts = version.trim().split("\\.");
        for (int index = 0; index < minimum.length; index++) {
            int part;
            try {
                part = index < parts.length ? Integer.parseInt(parts[index].replaceAll("\\D.*$", "")) : 0;
            } catch (NumberFormatException e) {
                return false;
            }
            if (part != minimum[index]) {
                return part > minimum[index];
            }
        }
        return true;
    }
}
