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
package io.contexa.contexacore.autonomous.context.support;

import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.postretrieval.document.DocumentPostProcessor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * BR-S4: the past record post-processing step behind Spring AI's DocumentPostProcessor contract gives exactly what the
 * ranking gave before, whatever the query.
 */
class PastRecordPostProcessorTest {

    @Test
    void theRankedStepIsTheRankingWhateverTheQuery() {
        List<Document> records = records();

        DocumentPostProcessor step = PastRecordPostProcessor.ranked();

        assertThat(step.process(PastRecordPostProcessor.PAST_RECORDS, records))
                .containsExactlyElementsOf(PastRecordRanking.ranked(records));
        assertThat(step.process(new Query("path: /api/reports"), records))
                .containsExactlyElementsOf(PastRecordRanking.ranked(records));
    }

    @Test
    void theTopStepIsTheRankingCut() {
        List<Document> records = records();

        for (int limit = 0; limit <= records.size() + 1; limit++) {
            assertThat(PastRecordPostProcessor.top(limit).process(PastRecordPostProcessor.queryOf("q"), records))
                    .as("limit " + limit).containsExactlyElementsOf(PastRecordRanking.top(records, limit));
        }
    }

    @Test
    void noRecordsGiveNone() {
        assertThat(PastRecordPostProcessor.ranked().process(PastRecordPostProcessor.PAST_RECORDS, List.of())).isEmpty();
        assertThat(PastRecordPostProcessor.ranked().process(PastRecordPostProcessor.PAST_RECORDS, null)).isEmpty();
    }

    @Test
    void aBlankSearchTextGivesTheFixedQuery() {
        assertThat(PastRecordPostProcessor.queryOf(" ")).isSameAs(PastRecordPostProcessor.PAST_RECORDS);
        assertThat(PastRecordPostProcessor.queryOf("path: /x").text()).isEqualTo("path: /x");
    }

    private static List<Document> records() {
        List<Document> records = new ArrayList<>();
        records.add(record("d-1", "e-1", 0.80, "2026-10-01T10:00:00"));
        records.add(record("d-2", "e-2", 0.80, "2026-10-03T10:00:00"));
        records.add(record("d-3", "e-1", 0.95, "2026-10-01T10:00:00"));
        records.add(record("d-4", "e-4", 0.10, "2026-10-05T10:00:00"));
        records.add(record("d-5", "e-5", 0.80, "2026-10-03T10:00:00"));
        return records;
    }

    private static Document record(String id, String eventId, double score, String timestamp) {
        return Document.builder().id(id).text("User accessed /api/reports/" + eventId)
                .metadata(Map.of("eventId", eventId, "timestamp", timestamp)).score(score).build();
    }
}
