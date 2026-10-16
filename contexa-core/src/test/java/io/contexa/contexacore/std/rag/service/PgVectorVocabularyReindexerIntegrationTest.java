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

import io.contexa.contexacore.autonomous.context.support.VocabularyVersion;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.Embedding;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingRequest;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.ai.vectorstore.pgvector.PgVectorStore;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** W5-7 D5 on a real pgvector table: documents of another vocabulary are moved into today's under their own IDs. */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_PGVECTOR_URL", matches = ".+")
class PgVectorVocabularyReindexerIntegrationTest {

    private static final String TABLE = "w57_vocabulary_reindex";
    private static final String UNSTAMPED_ID = "00000000-0000-0000-0000-000000000001";

    private JdbcTemplate jdbc;
    private PgVectorStore store;

    @BeforeEach
    void setUp() throws Exception {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(System.getenv("CONTEXA_TEST_PGVECTOR_URL"),
                System.getenv("CONTEXA_TEST_PGVECTOR_USERNAME"), System.getenv("CONTEXA_TEST_PGVECTOR_PASSWORD"));
        jdbc = new JdbcTemplate(dataSource);
        store = PgVectorStore.builder(jdbc, new FixedEmbeddingModel())
                .dimensions(3)
                .distanceType(PgVectorStore.PgDistanceType.COSINE_DISTANCE)
                .indexType(PgVectorStore.PgIndexType.NONE)
                .initializeSchema(true)
                .removeExistingVectorStoreTable(true)
                .vectorTableName(TABLE)
                .build();
        store.afterPropertiesSet();
        Map<String, Object> unstamped = new HashMap<>(Map.of(
                "documentType", "behavior", "userId", "alice", "actionFamily", "CREATE",
                "ipBand", "10.40.12", "pathFamily", "/api/projects/123/exports"));
        Map<String, Object> current = new HashMap<>(unstamped);
        current.put("actionFamily", "WRITE");
        current.put("vocabularyVersion", VocabularyVersion.CURRENT);
        Map<String, Object> threat = new HashMap<>(unstamped);
        threat.put("documentType", "threat");
        store.add(List.of(
                new Document(UNSTAMPED_ID, "record one", unstamped),
                new Document("00000000-0000-0000-0000-000000000002", "record two", current),
                new Document("00000000-0000-0000-0000-000000000003", "record three", threat)));
    }

    @AfterEach
    void tearDown() {
        jdbc.execute("DROP TABLE IF EXISTS public." + TABLE);
    }

    @Test
    void theDocumentsOfAnotherVocabularyAreMovedUnderTheirOwnIds() {
        PgVectorVocabularyReindexer reindexer = new PgVectorVocabularyReindexer(store, "public", TABLE);

        assertThat(reindexer.reindex(1)).isEqualTo(2);
        assertThat(reindexer.reindex(1)).isZero();

        Map<String, String> families = new HashMap<>();
        Map<String, String> versions = new HashMap<>();
        Map<String, String> contents = new HashMap<>();
        jdbc.query("select id::text as id, metadata::jsonb ->> 'actionFamily' as family, "
                        + "metadata::jsonb ->> 'vocabularyVersion' as version, content from public." + TABLE,
                rs -> {
                    families.put(rs.getString("id"), rs.getString("family"));
                    versions.put(rs.getString("id"), rs.getString("version"));
                    contents.put(rs.getString("id"), rs.getString("content"));
                });
        assertThat(families).containsOnly(
                Map.entry(UNSTAMPED_ID, "WRITE"),
                Map.entry("00000000-0000-0000-0000-000000000002", "WRITE"),
                Map.entry("00000000-0000-0000-0000-000000000003", "WRITE"));
        assertThat(versions.values()).containsOnly(VocabularyVersion.CURRENT);
        assertThat(contents).containsEntry(UNSTAMPED_ID, "record one");
        assertThat(jdbc.queryForObject("select metadata::jsonb ->> 'ipBand' from public." + TABLE
                + " where id::text = ?", String.class, UNSTAMPED_ID)).isEqualTo("10.40.12.0/24");
    }

    private static final class FixedEmbeddingModel implements EmbeddingModel {

        @Override
        public EmbeddingResponse call(EmbeddingRequest request) {
            List<Embedding> embeddings = new ArrayList<>();
            for (int index = 0; index < request.getInstructions().size(); index++) {
                embeddings.add(new Embedding(new float[] {1f, 0f, 0f}, index));
            }
            return new EmbeddingResponse(embeddings);
        }

        @Override
        public float[] embed(Document document) {
            return new float[] {1f, 0f, 0f};
        }

        @Override
        public int dimensions() {
            return 3;
        }
    }
}
