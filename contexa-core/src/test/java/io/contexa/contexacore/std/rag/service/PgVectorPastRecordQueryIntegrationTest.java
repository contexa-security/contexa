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
                        Map.of("retrievalPurpose", "other")),
                // docs/agent A3-1, A3-2: a tenant's records, an agent's record and a quarantined one.
                with(record("00000000-0000-0000-0000-000000000011", "/api/projects/GB-500/exports", "2026-10-12T09:00:00", "s-old"),
                        Map.of("tenantId", "t-1")),
                with(record("00000000-0000-0000-0000-000000000012", "/api/projects/GB-500/exports", "2026-10-12T08:00:00", "s-old"),
                        Map.of("tenantId", "t-2")),
                with(record("00000000-0000-0000-0000-000000000013", "/api/projects/GB-500/exports", "2026-10-12T07:00:00", "s-old"),
                        Map.of("agentId", "agt-1", "subjectKind", "DELEGATED_AGENT")),
                with(record("00000000-0000-0000-0000-000000000014", "/api/projects/GB-500/exports", "2026-10-12T06:00:00", "s-old"),
                        Map.of("learningState", "QUARANTINED"))));
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

    /**
     * docs/agent A3-1, A3-2: a person's lookup reads no agent's records, its tenant's records and the records bound to
     * no tenant, as the document authorization reads a tenant; a request of no tenant reads no tenant's records. A
     * quarantined record is never read.
     */
    @Test
    void aPersonsLookupReadsItsTenantsRecordsAndNoAgentsAndNoQuarantinedOnes() {
        PastRecordScope tenant = new PastRecordScope(USER, PURPOSE, "EXPORT", List.of("s-now"), "t-1", null, null);

        assertThat(query.records(tenant, List.of(), 20)).extracting(Document::getId).containsExactly(
                "00000000-0000-0000-0000-000000000002",
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000011",
                "00000000-0000-0000-0000-000000000003",
                "00000000-0000-0000-0000-000000000004");
        assertThat(query.groups(tenant)).filteredOn(group -> "/api/projects/GB-500/exports".equals(group.path()))
                .extracting(PastRecordGroup::records).containsExactly(3L);
        assertThat(query.records(scope(), List.of(), 20)).extracting(Document::getId)
                .doesNotContain("00000000-0000-0000-0000-000000000011", "00000000-0000-0000-0000-000000000012",
                        "00000000-0000-0000-0000-000000000013", "00000000-0000-0000-0000-000000000014");
    }

    /** docs/agent A3-1: an agent's lookup reads that agent's records only. */
    @Test
    void anAgentsLookupReadsThatAgentsRecordsOnly() {
        PastRecordScope agent = new PastRecordScope(USER, PURPOSE, "EXPORT", List.of("s-now"), null, null, "agt-1");

        assertThat(query.records(agent, List.of(), 20)).extracting(Document::getId)
                .containsExactly("00000000-0000-0000-0000-000000000013");
        assertThat(query.groups(new PastRecordScope(USER, PURPOSE, "EXPORT", List.of("s-now"), null, null, "agt-2")))
                .isEmpty();
    }

    /**
     * docs/agent A3-8: the records of an agent, or of one of its delegations, are quarantined and so never read; a
     * release gives them back the learning state they had (a held record stays held) but keeps the records of a
     * delegation still quarantined; a removal deletes them. The records of people and other agents stay.
     */
    @Test
    void anAgentsRecordsAreQuarantinedReleasedAndRemovedAlone() {
        store.add(List.of(
                with(record("00000000-0000-0000-0000-000000000015", "/api/projects/GB-500/exports", "2026-10-12T05:00:00", "s-old"),
                        Map.of("agentId", "agt-1", "delegationId", "dlg-1")),
                with(record("00000000-0000-0000-0000-000000000016", "/api/projects/GB-500/exports", "2026-10-12T04:00:00", "s-old"),
                        Map.of("agentId", "agt-1", "delegationId", "dlg-2", "learningState", "HELD")),
                with(record("00000000-0000-0000-0000-000000000017", "/api/projects/GB-500/exports", "2026-10-12T03:00:00", "s-old"),
                        Map.of("agentId", "agt-2", "delegationId", "dlg-1"))));
        PastRecordScope agent = new PastRecordScope(USER, PURPOSE, "EXPORT", List.of("s-now"), null, null, "agt-1");
        List<String> person = ids(query.records(scope(), List.of(), 20));

        assertThat(query.quarantineAgentRecords("agt-1", "dlg-1")).isEqualTo(1);
        assertThat(ids(query.records(agent, List.of(), 20))).containsExactly("00000000-0000-0000-0000-000000000013");
        // The agent's quarantine changes the records not quarantined yet, the held one included.
        assertThat(query.quarantineAgentRecords("agt-1", null)).isEqualTo(2);
        assertThat(query.records(agent, List.of(), 20)).isEmpty();
        assertThat(learningState("00000000-0000-0000-0000-000000000016")).isEqualTo("QUARANTINED");

        // dlg-1 stays quarantined: releasing the agent keeps its record.
        assertThat(query.releaseAgentRecords("agt-1", null, List.of("dlg-1"))).isEqualTo(2);
        assertThat(ids(query.records(agent, List.of(), 20))).containsExactly("00000000-0000-0000-0000-000000000013");
        assertThat(learningState("00000000-0000-0000-0000-000000000016")).isEqualTo("HELD");
        assertThat(learningState("00000000-0000-0000-0000-000000000015")).isEqualTo("QUARANTINED");
        assertThat(query.releaseAgentRecords("agt-1", "dlg-1", List.of())).isEqualTo(1);
        assertThat(ids(query.records(agent, List.of(), 20))).containsExactly(
                "00000000-0000-0000-0000-000000000013", "00000000-0000-0000-0000-000000000015");
        assertThat(jdbc.queryForObject("select count(*) from public." + TABLE
                + " where jsonb_exists(metadata::jsonb, 'learningStateBeforeQuarantine')", Long.class)).isZero();

        assertThat(query.removeAgentRecords("agt-1", "dlg-2")).isEqualTo(1);
        assertThat(query.removeAgentRecords("agt-1", null)).isEqualTo(2);
        assertThat(jdbc.queryForObject("select count(*) from public." + TABLE
                + " where metadata::jsonb ->> 'agentId' = 'agt-1'", Long.class)).isZero();
        // Another agent's record of the same delegation id and the person's records stay.
        assertThat(jdbc.queryForObject("select count(*) from public." + TABLE
                + " where metadata::jsonb ->> 'agentId' = 'agt-2'", Long.class)).isEqualTo(1L);
        assertThat(ids(query.records(scope(), List.of(), 20))).isEqualTo(person);
    }

    @Test
    void aStoreThatIsNotPgvectorCannotAnswer() {
        PastRecordQuery other = new PgVectorPastRecordQuery(mock(VectorStore.class), "public", TABLE);

        assertThat(other.available()).isFalse();
        assertThat(PastRecordQuery.unavailable().available()).isFalse();
    }

    private String learningState(String id) {
        return jdbc.queryForObject("select metadata::jsonb ->> 'learningState' from public." + TABLE
                + " where id = cast(? as uuid)", String.class, id);
    }

    private static List<String> ids(List<Document> documents) {
        return documents.stream().map(Document::getId).toList();
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
