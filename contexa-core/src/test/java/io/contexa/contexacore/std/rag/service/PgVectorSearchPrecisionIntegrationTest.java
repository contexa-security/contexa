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
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
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
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * W2-15 on a real pgvector: with an approximate index the filter is applied after the index is scanned, so a search
 * scoped to one user loses that user's records once the planner walks the HNSW index. At production size the planner
 * walks the index on its own (the W2-15 experiment, 200,000 records: one record of twenty); on this small table the
 * session makes reading the whole table as dear as at that size ({@code seq_page_cost}), so that the searches meet
 * the production plan. Scans stay enabled: turning one off is the exact search's own setting.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_PGVECTOR_URL", matches = ".+")
class PgVectorSearchPrecisionIntegrationTest {

    private static final String TABLE = "w215_precision";

    private final FilterExpressionBuilder filter = new FilterExpressionBuilder();
    private SingleConnectionDataSource dataSource;
    private JdbcTemplate jdbc;
    private PgVectorStore store;

    @BeforeEach
    void setUp() throws Exception {
        dataSource = new SingleConnectionDataSource(System.getenv("CONTEXA_TEST_PGVECTOR_URL"),
                System.getenv("CONTEXA_TEST_PGVECTOR_USERNAME"), System.getenv("CONTEXA_TEST_PGVECTOR_PASSWORD"), true);
        jdbc = new JdbcTemplate(dataSource);
        store = PgVectorStore.builder(jdbc, new QueryEmbeddingModel())
                .dimensions(3)
                .distanceType(PgVectorStore.PgDistanceType.COSINE_DISTANCE)
                .indexType(PgVectorStore.PgIndexType.HNSW)
                .initializeSchema(true)
                .removeExistingVectorStoreTable(true)
                .vectorTableName(TABLE)
                .build();
        store.afterPropertiesSet();
        // 2,000 records of 200 users (ten each) in two organisations, all within ninety degrees of the query; the
        // organisation alternates every ten records, so that the records nearest the query belong to both.
        jdbc.execute("INSERT INTO public." + TABLE + " (id, content, metadata, embedding) "
                + "SELECT md5(g::text)::uuid, 'record ' || g, json_build_object('userId', 'u' || (g % 200), "
                + "'organizationId', 'org-' || ((g / 10) % 2), 'documentType', 'behavior'), "
                + "('[' || (1 + (g % 10) * 0.1) || ',' || (0.5 * sin(g * 0.37)) || ',' || (0.5 * cos(g * 0.37)) || ']')::vector "
                + "FROM generate_series(1, 2000) g");
        jdbc.execute("ANALYZE public." + TABLE);
        jdbc.execute("SET seq_page_cost = 1000");
    }

    @AfterEach
    void tearDown() {
        jdbc.execute("RESET seq_page_cost");
        jdbc.execute("DROP TABLE IF EXISTS public." + TABLE);
        dataSource.destroy();
    }

    @Test
    @DisplayName("a search scoped to one user finds every nearest record of that user even where the index is walked (W2-15)")
    void aPersonalSearchFindsEveryNearestRecordOfTheUser() {
        List<Document> found = layer().similaritySearch(SearchRequest.builder().query("record").topK(10)
                .similarityThresholdAll()
                .filterExpression(filter.and(filter.and(filter.eq("documentType", "behavior"), filter.eq("userId", "u7")),
                        filter.nin("sessionId", "session-now")).build())
                .build());

        assertThat(found).hasSize(10);
        assertThat(found).allSatisfy(document -> assertThat(document.getMetadata()).containsEntry("userId", "u7"));
    }

    @Test
    @DisplayName("a broad search keeps walking the index until it has as many records as asked (W2-15)")
    void aBroadSearchKeepsWalkingTheIndexUntilItHasEnoughRecords() {
        // One in two records is the organisation's: a candidate list of 100 holds about 50 of them, so 60 needs the
        // index walk to go on past the candidate list.
        List<Document> found = layer().similaritySearch(SearchRequest.builder().query("record").topK(60)
                .similarityThresholdAll()
                .filterExpression(filter.and(filter.eq("documentType", "behavior"), filter.eq("organizationId", "org-1")).build())
                .build());

        assertThat(found).hasSize(60);
        assertThat(found).allSatisfy(document -> assertThat(document.getMetadata()).containsEntry("organizationId", "org-1"));
    }

    @Test
    @DisplayName("the metadata index is created once and is the one a personal search reads (W2-15)")
    void theMetadataIndexIsCreatedOnceAndServesThePersonalSearch() {
        PgVectorMetadataIndex.ensure(jdbc, "public", TABLE);
        PgVectorMetadataIndex.ensure(jdbc, "public", TABLE);
        jdbc.execute("ANALYZE public." + TABLE);

        assertThat(jdbc.queryForObject("SELECT count(*) FROM pg_indexes WHERE tablename = ? AND indexname = ?",
                Integer.class, TABLE, TABLE + "_metadata_path_idx")).isEqualTo(1);
        List<String> plan = jdbc.queryForList("EXPLAIN SELECT id FROM public." + TABLE
                + " WHERE \"metadata\"::jsonb @@ '$.userId == \"u7\"'::jsonpath", String.class);
        assertThat(String.join("\n", plan)).contains(TABLE + "_metadata_path_idx");
    }

    @Test
    @DisplayName("storing an event's record again overwrites its row instead of adding a second one (W2-15)")
    void storingAnEventsRecordAgainOverwritesItsRow() {
        UnifiedVectorService service = new UnifiedVectorService(new PgVectorStoreProperties(), layer(), store);

        service.storeDocument(new Document("first", Map.of("documentType", "behavior", "eventId", "event-again",
                "userId", "u-again")));
        service.storeDocument(new Document("again", Map.of("documentType", "behavior", "eventId", "event-again",
                "userId", "u-again")));

        assertThat(jdbc.queryForList("SELECT content FROM public." + TABLE + " WHERE metadata->>'eventId' = ?",
                String.class, "event-again")).containsExactly("again");
    }

    @Test
    @DisplayName("a schema or table name that is not a plain identifier is refused (W2-15)")
    void anUnsafeNameIsRefused() {
        assertThatThrownBy(() -> PgVectorMetadataIndex.ensure(jdbc, "public; DROP TABLE x", TABLE))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PgVectorMetadataIndex.ensure(jdbc, "public", "t\"x"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private VectorStoreCacheLayer layer() {
        VectorStoreCacheLayer layer = new VectorStoreCacheLayer(store, new TieredStrategyProperties(),
                new PgVectorSearchSettings(new PgVectorStoreProperties()));
        layer.init();
        return layer;
    }

    /** Every text embeds to the query direction. */
    private static final class QueryEmbeddingModel implements EmbeddingModel {

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
