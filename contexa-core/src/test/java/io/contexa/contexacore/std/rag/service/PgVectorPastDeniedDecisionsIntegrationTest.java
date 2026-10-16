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

import io.contexa.contexacore.autonomous.context.support.PastDeniedDecisions;
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
import org.springframework.ai.vectorstore.pgvector.PgVectorStore;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W5-4 on a real pgvector table: the user's recent decisions that did not allow are read by an exact lookup of the
 * action family, outside the session, within the window, the latest first; a verification writes its outcome on the
 * decision's record.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_PGVECTOR_URL", matches = ".+")
class PgVectorPastDeniedDecisionsIntegrationTest {

    private static final String TABLE = "w54_past_denied";
    private static final String PURPOSE = "security_investigation";

    private JdbcTemplate jdbc;
    private PgVectorStore store;
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
                record("01", "suspicious", "alice", "EXPORT", "2026-10-12T03:17:00", "s-old"),
                record("02", "threat", "alice", "EXPORT", "2026-10-11T03:17:00", "s-old"),
                record("03", "ambiguous", "alice", "EXPORT", "2026-10-10T03:17:00", "s-old"),
                record("04", "suspicious", "alice", "EXPORT", "2026-10-09T03:17:00", "s-old"),
                // Outside the window, an allowed record, another user, another action, the request's session.
                record("05", "suspicious", "alice", "EXPORT", "2026-09-01T03:17:00", "s-old"),
                record("06", "behavior", "alice", "EXPORT", "2026-10-12T04:00:00", "s-old"),
                record("07", "suspicious", "bob", "EXPORT", "2026-10-12T05:00:00", "s-old"),
                record("08", "suspicious", "alice", "READ", "2026-10-12T06:00:00", "s-old"),
                record("09", "suspicious", "alice", "EXPORT", "2026-10-13T03:17:00", "s-now")));
        query = new PgVectorPastRecordQuery(store, "public", TABLE);
    }

    @AfterEach
    void tearDown() {
        jdbc.execute("DROP TABLE IF EXISTS public." + TABLE);
    }

    @Test
    void theRecentDecisionsThatDidNotAllowAreReadLatestFirst() {
        List<Document> denied = query.deniedDecisions(new PastRecordScope("alice", PURPOSE, "EXPORT", List.of("s-now")),
                LocalDateTime.of(2026, 9, 14, 3, 17), PastDeniedDecisions.LIMIT);

        assertThat(denied).extracting(Document::getId).containsExactly(id("01"), id("02"), id("03"));
    }

    @Test
    void aVerificationWritesItsOutcomeOnTheDecisionsRecord() {
        assertThat(query.recordOutcome(id("01"), PastDeniedDecisions.VERIFIED_BY_STEP_UP)).isTrue();
        assertThat(query.recordOutcome("00000000-0000-0000-0000-000000000099", PastDeniedDecisions.VERIFIED_BY_STEP_UP))
                .isFalse();

        assertThat(jdbc.queryForObject("select metadata::jsonb ->> '" + PastDeniedDecisions.OUTCOME_KEY + "' from public."
                + TABLE + " where id::text = ?", String.class, id("01"))).isEqualTo(PastDeniedDecisions.VERIFIED_BY_STEP_UP);
        assertThat(jdbc.queryForObject("select metadata::jsonb ->> 'userId' from public." + TABLE + " where id::text = ?",
                String.class, id("01"))).isEqualTo("alice");
    }

    private static String id(String suffix) {
        return "00000000-0000-0000-0000-0000000000" + suffix;
    }

    private static Document record(String suffix, String type, String user, String action, String timestamp,
                                   String session) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("documentType", type);
        metadata.put("userId", user);
        metadata.put("retrievalPurpose", PURPOSE);
        metadata.put("actionFamily", action);
        metadata.put("pathFamily", "/api/projects/{projectKey}/exports");
        metadata.put("requestPath", "/api/projects/GB-500/exports");
        metadata.put("timestamp", timestamp);
        metadata.put("sessionId", session);
        metadata.put("action", "threat".equals(type) ? "BLOCK" : "behavior".equals(type) ? "ALLOW" : "CHALLENGE");
        return new Document(id(suffix), "record " + suffix, metadata);
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
