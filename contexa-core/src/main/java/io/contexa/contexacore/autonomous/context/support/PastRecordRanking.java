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

import io.contexa.contexacommon.domain.EventTimeZone;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The order of retrieved past records (W3-3). A vector store orders by distance alone, so documents at the same
 * distance come back in whatever order the plan and the storage give (W0-8). The records are ranked here by fixed
 * keys instead: the higher similarity first, then the latest record, then the stored document ID; and the copies of one
 * record (the same event, else the same text) take one place, the best ranked one. A record the prompt context
 * authorization made again has a new document ID and no score, so the stored ID and the score it was found with are
 * read from its metadata.
 */
public final class PastRecordRanking {

    private static final Comparator<Document> ORDER = Comparator
            .comparingDouble(PastRecordRanking::similarity).reversed()
            .thenComparing(PastRecordRanking::recordedAt, Comparator.reverseOrder())
            .thenComparing(PastRecordRanking::storedId);

    private PastRecordRanking() {
    }

    /** The first records of the ranking, copies of one record counted once. */
    public static List<Document> top(List<Document> documents, int limit) {
        List<Document> ranked = ranked(documents);
        return ranked.size() <= Math.max(0, limit) ? ranked : List.copyOf(ranked.subList(0, Math.max(0, limit)));
    }

    /** Every record in ranking order, copies of one record counted once. */
    public static List<Document> ranked(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return List.of();
        }
        List<Document> sorted = new ArrayList<>(documents.stream().filter(Objects::nonNull).toList());
        sorted.sort(ORDER);
        Map<String, Document> byRecord = new LinkedHashMap<>();
        for (Document document : sorted) {
            byRecord.putIfAbsent(recordKey(document), document);
        }
        return List.copyOf(byRecord.values());
    }

    /** One record's key: its event, else its text, else its stored document ID. */
    public static String recordKey(Document document) {
        Map<String, Object> metadata = document.getMetadata();
        Object eventId = metadata != null ? metadata.get(VectorDocumentMetadata.EVENT_ID) : null;
        if (eventId != null && StringUtils.hasText(eventId.toString())) {
            return "event:" + eventId.toString().trim();
        }
        if (StringUtils.hasText(document.getText())) {
            return "text:" + document.getText().trim();
        }
        return "id:" + storedId(document);
    }

    /** The ID the record is stored under: the metadata ID, else the document ID. */
    public static String storedId(Document document) {
        Map<String, Object> metadata = document.getMetadata();
        Object id = metadata != null ? metadata.get(VectorDocumentMetadata.ID) : null;
        if (id != null && StringUtils.hasText(id.toString())) {
            return id.toString().trim();
        }
        return document.getId() == null ? "" : document.getId();
    }

    /**
     * The similarity: the document's score, else the score it was found with (the metadata similarity score), else the
     * metadata score, else one minus the metadata distance, else 0.
     */
    public static double similarity(Document document) {
        Double similarity = similarityOrNull(document);
        return similarity != null ? similarity : 0.0d;
    }

    /** The similarity, or null when the store gave none (a record read without a search has none). */
    public static Double similarityOrNull(Document document) {
        if (document.getScore() != null) {
            return document.getScore();
        }
        Map<String, Object> metadata = document.getMetadata();
        if (metadata == null) {
            return null;
        }
        if (metadata.get(VectorDocumentMetadata.SIMILARITY_SCORE) instanceof Number found) {
            return found.doubleValue();
        }
        if (metadata.get("score") instanceof Number score) {
            return score.doubleValue();
        }
        if (metadata.get("distance") instanceof Number distance) {
            return 1.0d - distance.doubleValue();
        }
        return null;
    }

    /** When the record was made, on the event clock it was stored with, or null. */
    public static LocalDateTime recordedAtOrNull(Map<String, Object> metadata) {
        Object value = metadata != null ? metadata.get(VectorDocumentMetadata.TIMESTAMP) : null;
        if (value == null || !StringUtils.hasText(value.toString())) {
            return null;
        }
        String text = value.toString().trim();
        try {
            return LocalDateTime.parse(text);
        }
        catch (RuntimeException notLocal) {
            try {
                return LocalDateTime.ofInstant(Instant.parse(text), EventTimeZone.get());
            }
            catch (RuntimeException notInstant) {
                try {
                    return LocalDateTime.ofInstant(OffsetDateTime.parse(text).toInstant(), EventTimeZone.get());
                }
                catch (RuntimeException unreadable) {
                    return null;
                }
            }
        }
    }

    private static LocalDateTime recordedAt(Document document) {
        LocalDateTime at = recordedAtOrNull(document.getMetadata());
        return at != null ? at : LocalDateTime.MIN;
    }
}
