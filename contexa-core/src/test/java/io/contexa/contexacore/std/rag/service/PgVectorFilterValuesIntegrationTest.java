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

import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.Embedding;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingRequest;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.ai.vectorstore.pgvector.PgVectorStore;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * P2 correction 6: with Spring AI 1.1.5 or later the pgvector filter converter escapes keys and values itself
 * (CVE-2026-22729, CVE-2026-40967), so the engine passes a filter value as it is. A user id with a quote, a double
 * quote or a backslash finds and deletes exactly its own records in a real pgvector table. Runs against an isolated
 * database given by CONTEXA_TEST_PGVECTOR_URL, _USERNAME and _PASSWORD.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_PGVECTOR_URL", matches = ".+")
class PgVectorFilterValuesIntegrationTest {

    private static final String TABLE = "p2_filter_values";
    private static final List<String> USERS = List.of("o'brien", "say \"hi\"", "a\\b", "plain-user");

    private PgVectorStore store;
    private JdbcTemplate jdbc;

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
        List<Document> documents = new ArrayList<>();
        for (String user : USERS) {
            documents.add(new Document("record of " + user, Map.of("userId", user, "documentType", "behavior")));
        }
        store.add(documents);
    }

    @AfterEach
    void tearDown() {
        jdbc.execute("DROP TABLE IF EXISTS public." + TABLE);
    }

    @Test
    void theEnginesSearchFindsExactlyTheRecordsOfAUserWhoseIdHoldsQuotesOrABackslash() {
        VectorStoreCacheLayer layer = new VectorStoreCacheLayer(store, new TieredStrategyProperties());
        layer.init();
        FilterExpressionBuilder filter = new FilterExpressionBuilder();

        for (String user : USERS) {
            List<Document> found = layer.similaritySearch(SearchRequest.builder().query("record").topK(10)
                    .similarityThresholdAll().filterExpression(filter.eq("userId", user).build()).build());
            assertThat(found).as(user).extracting(document -> document.getMetadata().get("userId")).containsExactly(user);
        }
        // An injected value matches nothing instead of widening the query.
        assertThat(layer.similaritySearch(SearchRequest.builder().query("record").topK(10).similarityThresholdAll()
                .filterExpression(filter.eq("userId", "x\" || $.userId == \"plain-user").build()).build())).isEmpty();
    }

    @Test
    void aDeletionByAUserIdWithAQuoteRemovesOnlyThatUsersRecords() {
        store.delete(new FilterExpressionBuilder().eq("userId", "o'brien").build());

        assertThat(jdbc.queryForList("SELECT metadata->>'userId' FROM public." + TABLE + " ORDER BY 1", String.class))
                .containsExactlyInAnyOrder("say \"hi\"", "a\\b", "plain-user");
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
