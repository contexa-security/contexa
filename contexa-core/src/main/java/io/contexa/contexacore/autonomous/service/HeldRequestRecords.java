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
package io.contexa.contexacore.autonomous.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.LearningPromotionPolicy;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The facts of a request kept to be learned later: after a verification (W5-2) or after its first-seen values are
 * promoted (W5-1). The canonical context is not kept; the item count and network zone the decision used are kept as
 * plain values in its place, and so is any other plain metadata value. A held request's learning mark is not kept.
 */
final class HeldRequestRecords {

    /** The identity values of the request's decision (W5-1), which a verification on the request vouches for. */
    static final String IDENTITY_VALUES = "identityValues";
    /** The event id the held request had, kept on the decoded request whatever id it is given (W5-4). */
    static final String HELD_EVENT_ID = "heldEventId";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> RECORD = new TypeReference<>() {
    };

    private HeldRequestRecords() {
    }

    static String encode(SecurityEvent event) throws Exception {
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("eventId", event.getEventId());
        record.put("timestamp", event.getTimestamp() != null ? event.getTimestamp().toEpochMilli() : null);
        record.put("userId", event.getUserId());
        record.put("userName", event.getUserName());
        record.put("sessionId", event.getSessionId());
        record.put("sourceIp", event.getSourceIp());
        record.put("userAgent", event.getUserAgent());
        record.put("description", event.getDescription());
        Map<String, Object> metadata = new LinkedHashMap<>();
        if (event.getMetadata() != null) {
            event.getMetadata().forEach((key, value) -> {
                if (plain(value) && !VectorDocumentMetadata.LEARNING_STATE.equals(key)) {
                    metadata.put(key, value);
                }
            });
        }
        // The canonical context is not kept, so the item count and network zone the decision used (W3-3) are kept as
        // the plain values the later learning reads in its place.
        if (event.getMetadata() != null
                && event.getMetadata().get(LearningPromotionPolicy.DECIDED_CONTEXT) instanceof CanonicalSecurityContext decided) {
            if (decided.getResource() != null && decided.getResource().getRequestedItems() != null) {
                metadata.put("requestItems", decided.getResource().getRequestedItems());
            }
            if (decided.getLocation() != null && decided.getLocation().getNetworkZone() != null
                    && !decided.getLocation().getNetworkZone().isBlank()) {
                metadata.put("networkZone", decided.getLocation().getNetworkZone());
            }
            List<String> identity = LearningPromotionPolicy.identityValues(decided);
            if (!identity.isEmpty()) {
                metadata.put(IDENTITY_VALUES, identity);
            }
        }
        record.put("metadata", metadata);
        return JSON.writeValueAsString(record);
    }

    /**
     * The request the record keeps, under its own event id when asked (a promoted request replaces its held past
     * record), else under a new one.
     */
    @SuppressWarnings("unchecked")
    static SecurityEvent decode(String text, boolean keepEventId) throws Exception {
        Map<String, Object> record = JSON.readValue(text, RECORD);
        Object timestamp = record.get("timestamp");
        Object eventId = record.get("eventId");
        SecurityEvent event = SecurityEvent.builder()
                .eventId(keepEventId && eventId != null ? eventId.toString() : UUID.randomUUID().toString())
                .source(SecurityEvent.EventSource.IAM)
                .timestamp(timestamp instanceof Number at ? Instant.ofEpochMilli(at.longValue()) : null)
                .userId(text(record.get("userId")))
                .userName(text(record.get("userName")))
                .sessionId(text(record.get("sessionId")))
                .sourceIp(text(record.get("sourceIp")))
                .userAgent(text(record.get("userAgent")))
                .description(text(record.get("description")))
                .build();
        if (record.get("metadata") instanceof Map<?, ?> metadata) {
            ((Map<String, Object>) metadata).forEach(event::addMetadata);
        }
        if (eventId != null) {
            event.addMetadata(HELD_EVENT_ID, eventId.toString());
        }
        return event;
    }

    /** A value the record keeps as it is: text, a number, a truth value, or a list of them. */
    private static boolean plain(Object value) {
        if (value instanceof String || value instanceof Number || value instanceof Boolean) {
            return true;
        }
        if (value instanceof Collection<?> values) {
            return values.stream().allMatch(item -> item instanceof String || item instanceof Number
                    || item instanceof Boolean);
        }
        return false;
    }

    private static String text(Object value) {
        return value != null ? value.toString() : null;
    }
}
