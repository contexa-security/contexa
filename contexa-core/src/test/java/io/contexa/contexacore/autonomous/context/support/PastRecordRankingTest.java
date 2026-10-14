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

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W3-3: past records are chosen by fixed keys (similarity, then the latest record, then the document ID) and copies
 * of one record take one place, so the same input gives the same documents whatever order the store returns (W0-8).
 */
class PastRecordRankingTest {

    @Test
    void recordsAreRankedBySimilarityThenTheLatestThenTheDocumentId() {
        List<Document> documents = List.of(
                record("d1", "e1", 0.70, "2026-09-26T10:30"),
                record("d5", "e5", 0.80, "2026-09-21T10:30"),
                record("d4", "e4", 0.80, "2026-09-21T10:30"),
                record("d2", "e2", 0.90, "2026-09-20T10:30"),
                record("d3", "e3", 0.80, "2026-09-25T10:30"));

        assertThat(ids(PastRecordRanking.top(documents, 10))).containsExactly("d2", "d3", "d4", "d5", "d1");
    }

    @Test
    void copiesOfOneRecordTakeOnePlace() {
        List<Document> documents = List.of(
                record("d1", "e1", 0.80, "2026-09-26T10:30"),
                record("d2", "e1", 0.85, "2026-09-26T10:30"),
                record("d3", "e2", 0.60, "2026-09-25T10:30"),
                Document.builder().id("d4").text("same text").metadata(Map.of("documentType", "behavior")).score(0.50).build(),
                Document.builder().id("d5").text("same text").metadata(Map.of("documentType", "behavior")).score(0.40).build());

        assertThat(ids(PastRecordRanking.top(documents, 10))).containsExactly("d2", "d3", "d4");
    }

    @Test
    void aTieGroupGivesTheSameDocumentsWhateverTheInputOrder() {
        List<Document> documents = new ArrayList<>();
        for (int index = 1; index <= 8; index++) {
            documents.add(record("d0" + index, "e0" + index, 0.75, "2026-09-24T09:00"));
        }
        Random random = new Random(20261012L);
        for (int round = 0; round < 20; round++) {
            Collections.shuffle(documents, random);
            assertThat(ids(PastRecordRanking.top(documents, 3))).containsExactly("d01", "d02", "d03");
        }
    }

    @Test
    void theSimilarityIsTheScoreElseTheMetadataScoreElseOneMinusTheDistance() {
        Document scored = Document.builder().id("a").text("a").metadata(Map.of("eventId", "a")).score(0.40).build();
        Document metadataScore = new Document("b", "b", Map.of("eventId", "b", "score", 0.60));
        Document distance = new Document("c", "c", Map.of("eventId", "c", "distance", 0.10));

        assertThat(ids(PastRecordRanking.top(List.of(scored, metadataScore, distance), 3))).containsExactly("c", "b", "a");
    }

    /** A record the prompt context authorization made again has a new document ID; its stored ID ranks it. */
    @Test
    void aRecordMadeAgainWithAnotherDocumentIdKeepsItsPlaceByItsStoredId() {
        List<Document> documents = List.of(remade("x9", "d1"), remade("x8", "d2"), remade("x7", "d3"));
        List<Document> reversed = new ArrayList<>(documents);
        Collections.reverse(reversed);

        assertThat(storedIds(PastRecordRanking.ranked(documents))).containsExactly("d1", "d2", "d3");
        assertThat(storedIds(PastRecordRanking.ranked(reversed))).containsExactly("d1", "d2", "d3");
    }

    /** A record made again has no score of its own; the score it was found with is kept as its similarity score. */
    @Test
    void theSimilarityOfARecordMadeAgainIsTheScoreItWasFoundWith() {
        Document higher = new Document("x1", "a", Map.of("eventId", "a", "similarityScore", 0.90, "distance", 0.30));
        Document lower = new Document("x2", "b", Map.of("eventId", "b", "similarityScore", 0.80, "distance", 0.10));

        assertThat(ids(PastRecordRanking.top(List.of(lower, higher), 2))).containsExactly("x1", "x2");
    }

    private static Document remade(String documentId, String storedId) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("id", storedId);
        metadata.put("documentType", "behavior");
        metadata.put("eventId", "event-" + storedId);
        metadata.put("timestamp", "2026-09-24T09:00");
        metadata.put("similarityScore", 0.75);
        return new Document(documentId, "record " + storedId, metadata);
    }

    private static List<String> storedIds(List<Document> documents) {
        return documents.stream().map(document -> String.valueOf(document.getMetadata().get("id"))).toList();
    }

    private static Document record(String id, String eventId, double score, String timestamp) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("documentType", "behavior");
        metadata.put("eventId", eventId);
        metadata.put("timestamp", timestamp);
        return Document.builder().id(id).text("record " + eventId).metadata(metadata).score(score).build();
    }

    private static List<String> ids(List<Document> documents) {
        return documents.stream().map(Document::getId).toList();
    }
}
