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

import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The user's recent decisions that did not allow, as the past records block states them (W5-4, Q-57 decision 4): the
 * suspicious, threat and ambiguous records of the request's action family in the last {@value #WINDOW_DAYS} days,
 * outside the request's session, the latest first, at most {@value #LIMIT}. They are facts only; nothing is learned
 * from them.
 *
 * @param entries the decisions, the latest first
 */
public record PastDeniedDecisions(List<Entry> entries) {

    /**
     * The event metadata key of the decisions; its 'rag' prefix brings it back from the copy of the event the Layer1 past
     * record search runs on, as the past record counts are (W5-4).
     */
    public static final String EVENT_METADATA_KEY = "ragPastDeniedDecisions";
    public static final int LIMIT = 3;
    public static final int WINDOW_DAYS = 30;
    /** The record kinds of the decisions that did not allow: CHALLENGE, BLOCK and ESCALATE or a pending analysis. */
    public static final List<String> DOCUMENT_TYPES = List.of("suspicious", "threat", "ambiguous");
    /** The metadata key a verification or a release writes on the record of the decision it lifted. */
    public static final String OUTCOME_KEY = "verificationOutcome";
    public static final String VERIFIED_BY_STEP_UP = "verified by step-up";
    public static final String RELEASED_BY_ADMINISTRATOR = "released by an administrator";
    public static final String NOT_VERIFIED = "not verified";

    public PastDeniedDecisions {
        entries = entries == null ? List.of() : List.copyOf(entries);
    }

    /**
     * One decision that did not allow.
     *
     * @param at            when the request was made, on the event clock, null when not recorded
     * @param actionFamily  the request's action family
     * @param target        the request's target as the past records state it
     * @param decidedAction the action decided
     * @param outcome       how it ended: verified by step-up, released by an administrator, or not verified
     */
    public record Entry(LocalDateTime at, String actionFamily, String target, String decidedAction, String outcome) {
    }

    /**
     * The stored IDs the record of the request's decision that did not allow may have, one per record kind (the store
     * keeps one record per kind and event, W2-15); empty without the event.
     */
    public static List<String> documentIds(String eventId) {
        if (eventId == null || eventId.isBlank()) {
            return List.of();
        }
        return DOCUMENT_TYPES.stream()
                .map(type -> UUID.nameUUIDFromBytes((type + ":" + eventId.trim()).getBytes(StandardCharsets.UTF_8))
                        .toString())
                .toList();
    }

    /** The decisions of the records, in their order, at most {@value #LIMIT}. */
    public static PastDeniedDecisions of(List<Document> documents) {
        List<Entry> entries = new ArrayList<>();
        if (documents != null) {
            for (Document document : documents) {
                if (document == null) {
                    continue;
                }
                Map<String, Object> metadata = document.getMetadata() != null ? document.getMetadata() : Map.of();
                PastRecordRelevance.Subject record = PastRecordRelevance.Subject.ofRecord(metadata, document.getText());
                entries.add(new Entry(PastRecordRanking.recordedAtOrNull(metadata), text(metadata.get("actionFamily")),
                        record.target(),
                        firstText(text(metadata.get("autonomousAction")), text(metadata.get("action"))),
                        firstText(text(metadata.get(OUTCOME_KEY)), NOT_VERIFIED)));
                if (entries.size() == LIMIT) {
                    break;
                }
            }
        }
        return new PastDeniedDecisions(entries);
    }

    /** The decisions as event and execution metadata. */
    public List<Map<String, Object>> toMetadata() {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Entry entry : entries) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("at", entry.at() != null ? entry.at().toString() : null);
            row.put("actionFamily", entry.actionFamily());
            row.put("target", entry.target());
            row.put("decidedAction", entry.decidedAction());
            row.put("outcome", entry.outcome());
            rows.add(row);
        }
        return rows;
    }

    /** The decisions metadata states, none when it states none. */
    public static PastDeniedDecisions fromMetadata(Object value) {
        List<Entry> entries = new ArrayList<>();
        if (value instanceof List<?> rows) {
            for (Object row : rows) {
                if (row instanceof Map<?, ?> fields) {
                    entries.add(new Entry(time(fields.get("at")), text(fields.get("actionFamily")),
                            text(fields.get("target")), text(fields.get("decidedAction")),
                            firstText(text(fields.get("outcome")), NOT_VERIFIED)));
                }
            }
        }
        return new PastDeniedDecisions(entries);
    }

    private static LocalDateTime time(Object value) {
        if (value == null || !StringUtils.hasText(value.toString())) {
            return null;
        }
        try {
            return LocalDateTime.parse(value.toString().trim());
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static String text(Object value) {
        return value != null && StringUtils.hasText(value.toString()) ? value.toString().trim() : null;
    }

    private static String firstText(String first, String second) {
        return first != null ? first : second;
    }
}
