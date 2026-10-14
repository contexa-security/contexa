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

import io.contexa.contexacore.autonomous.context.support.PastRecordGroup;
import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.context.support.PastRecordScope;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.Embedding;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingRequest;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.pgvector.PgVectorStore;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * W3-18 on a real pgvector table: the past records of a request are read by an exact metadata lookup, not a similarity
 * search: the user's own allowed records of the action family, outside the request's session and not held back.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_PGVECTOR_URL", matches = ".+")
class PgVectorPastRecordQueryIntegrationTest {

    private static final String TABLE = "w318_past_records";
    private static final String EXPORTS = "/api/projects/{projectKey}/exports";
    private static final String USER = "o'brien";
    private static final String PURPOSE = "security_investigation";

    private PgVectorStore store;
    private JdbcTemplate jdbc;
    private PastRecordQuery query;

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
        store.add(List.of(
                record("00000000-0000-0000-0000-000000000001", "/api/projects/GB-500/exports", "2026-10-12T10:00:00", "s-old"),
                record("00000000-0000-0000-0000-000000000002", "/api/projects/GB-500/exports", "2026-10-12T11:00:00", "s-old"),
                record("00000000-0000-0000-0000-000000000003", "/api/projects/PLM-OPS/exports", "2026-10-11T09:00:00", "s-old"),
                // The same time as record 3: the stored ID decides.
                record("00000000-0000-0000-0000-000000000004", "/api/projects/QA-1/exports", "2026-10-11T09:00:00", "s-old"),
                with(record("00000000-0000-0000-0000-000000000005", "/api/projects/GB-500/exports", "2026-10-12T12:00:00", "s-now"), Map.of()),
                with(record("00000000-0000-0000-0000-000000000006", "/api/projects/GB-500/exports", "2026-10-12T12:00:00", "s-old"),
                        Map.of("learningState", "HELD")),
                with(record("00000000-0000-0000-0000-000000000007", "/api/projects/GB-500/exports", "2026-10-12T12:00:00", "s-old"),
                        Map.of("userId", "bob")),
                with(record("00000000-0000-0000-0000-000000000008", "/api/projects/GB-500/exports", "2026-10-12T12:00:00", "s-old"),
                        Map.of("actionFamily", "READ")),
                with(record("00000000-0000-0000-0000-000000000009", "/api/projects/GB-500/exports", "2026-10-12T12:00:00", "s-old"),
                        Map.of("documentType", "threat")),
                with(record("00000000-0000-0000-0000-000000000010", "/api/projects/GB-500/exports", "2026-10-12T12:00:00", "s-old"),
                        Map.of("retrievalPurpose", "other"))));
        query = new PgVectorPastRecordQuery(store, "public", TABLE);
    }

    @AfterEach
    void tearDown() {
        jdbc.execute("DROP TABLE IF EXISTS public." + TABLE);
    }

    @Test
    void theRecordsAreCountedByPathWithinTheUsersActionFamilyOutsideTheSessionAndNotHeldBack() {
        List<PastRecordGroup> groups = query.groups(scope());

        assertThat(query.available()).isTrue();
        assertThat(groups).containsExactlyInAnyOrder(
                new PastRecordGroup(EXPORTS, "/api/projects/GB-500/exports", "POST", 2, LocalDateTime.of(2026, 10, 12, 11, 0)),
                new PastRecordGroup(EXPORTS, "/api/projects/PLM-OPS/exports", "POST", 1, LocalDateTime.of(2026, 10, 11, 9, 0)),
                new PastRecordGroup(EXPORTS, "/api/projects/QA-1/exports", "POST", 1, LocalDateTime.of(2026, 10, 11, 9, 0)));
    }

    @Test
    void theRecordsOfTheFirstPathsComeFirstThenTheLatestThenTheStoredId() {
        List<Document> records = query.records(scope(), List.of("/api/projects/GB-500/exports"), 10);

        assertThat(records).extracting(Document::getId).containsExactly(
                "00000000-0000-0000-0000-000000000002",
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000003",
                "00000000-0000-0000-0000-000000000004");
        assertThat(records.get(0).getText()).isEqualTo("record /api/projects/GB-500/exports");
        assertThat(records.get(0).getMetadata())
                .containsEntry("userId", USER)
                .containsEntry("requestPath", "/api/projects/GB-500/exports")
                .doesNotContainKey("distance");
        assertThat(records.get(0).getScore()).isNull();
        assertThat(query.records(scope(), List.of(), 2)).extracting(Document::getId).containsExactly(
                "00000000-0000-0000-0000-000000000002",
                "00000000-0000-0000-0000-000000000001");
    }

    @Test
    void aStoreThatIsNotPgvectorCannotAnswer() {
        PastRecordQuery other = new PgVectorPastRecordQuery(mock(VectorStore.class), "public", TABLE);

        assertThat(other.available()).isFalse();
        assertThat(PastRecordQuery.unavailable().available()).isFalse();
    }

    private static PastRecordScope scope() {
        return new PastRecordScope(USER, PURPOSE, "EXPORT", List.of("s-now"));
    }

    private static Document record(String id, String path, String timestamp, String sessionId) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("documentType", "behavior");
        metadata.put("userId", USER);
        metadata.put("retrievalPurpose", PURPOSE);
        metadata.put("actionFamily", "EXPORT");
        metadata.put("pathFamily", EXPORTS);
        metadata.put("requestPath", path);
        metadata.put("httpMethod", "POST");
        metadata.put("timestamp", timestamp);
        metadata.put("sessionId", sessionId);
        metadata.put("eventId", "event-" + id.substring(id.length() - 2));
        return new Document(id, "record " + path, metadata);
    }

    private static Document with(Document document, Map<String, Object> changes) {
        Map<String, Object> metadata = new HashMap<>(document.getMetadata());
        metadata.putAll(changes);
        return new Document(document.getId(), document.getText(), metadata);
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
