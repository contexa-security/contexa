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
package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.baseline.BaselineViewCalculator;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.context.support.ActionFamilyResolver;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * One decision of a session, kept in the order the session made its requests: when the request was observed, what it
 * asked for and how it ended (a Zero Trust action, or {@link #AUTHORIZATION_DENIED} for a refused authorization),
 * with the request's target and item count (W2-5) so the session's work under an approval can be counted. Stored as
 * one tab-separated line; a line of the six fields written before reads without them.
 *
 * @param target the URL template's variables bound to the path ({@code projectKey=GB-500}), null without a template
 * @param items  how many items the request asked for, null when the host did not say
 */
public record SessionDecisionRecord(
        Instant at,
        String method,
        String path,
        String query,
        String actionFamily,
        String outcome,
        String target,
        Integer items) {

    public static final String AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED";

    /** The context metadata key under which the session's decisions travel as records (W2-5). */
    public static final String METADATA_KEY = "sessionDecisionRecords";

    private static final int FIELDS_BEFORE_W25 = 6;
    private static final int FIELDS = 8;

    /** A decision without a target or an item count. */
    public SessionDecisionRecord(Instant at, String method, String path, String query, String actionFamily,
                                 String outcome) {
        this(at, method, path, query, actionFamily, outcome, null, null);
    }

    /** The decision of an event's request, with its observed time and request facts. */
    public static SessionDecisionRecord of(SecurityEvent event, String outcome) {
        Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        String path = text(metadata.get("requestPath") != null ? metadata.get("requestPath") : metadata.get("fullPath"));
        String template = text(metadata.get("protectableResourceUrl") != null
                ? metadata.get("protectableResourceUrl") : metadata.get("resourceUrlTemplate"));
        return new SessionDecisionRecord(
                event.getTimestamp(),
                text(metadata.get("httpMethod")),
                path,
                text(metadata.get("queryString")),
                actionFamilyOf(metadata),
                outcome,
                BaselineViewCalculator.target(template, path),
                items(metadata.get("requestItems")));
    }

    private static Integer items(Object value) {
        if (value instanceof Number number) {
            return number.intValue() > 0 ? number.intValue() : null;
        }
        String text = text(value);
        if (text == null) {
            return null;
        }
        try {
            int items = Integer.parseInt(text.trim());
            return items > 0 ? items : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** The request's action family, the one the context gives it; null when no fact of the request names one. */
    private static String actionFamilyOf(Map<String, Object> metadata) {
        ActionFamily family = ActionFamilyResolver.resolve(metadata).family();
        return family != ActionFamily.UNKNOWN ? family.name() : null;
    }

    public String encode() {
        return String.join("\t", field(at != null ? at.toString() : null), field(method), field(path), field(query),
                field(actionFamily), field(outcome), field(target), field(items != null ? items.toString() : null));
    }

    /** The records a metadata value holds, in order; anything else in it is not a record. */
    public static List<SessionDecisionRecord> listOf(Object value) {
        List<SessionDecisionRecord> records = new ArrayList<>();
        if (value instanceof Collection<?> collection) {
            for (Object item : collection) {
                if (item instanceof SessionDecisionRecord record) {
                    records.add(record);
                }
            }
        }
        return records;
    }

    /** The record of a stored line; null when the line is not one. */
    public static SessionDecisionRecord decode(String line) {
        if (line == null) {
            return null;
        }
        String[] fields = line.split("\t", -1);
        if (fields.length != FIELDS && fields.length != FIELDS_BEFORE_W25) {
            return null;
        }
        Instant at;
        try {
            at = fields[0].isEmpty() ? null : Instant.parse(fields[0]);
        } catch (RuntimeException e) {
            return null;
        }
        // A family stored before the one vocabulary (CREATE, UPDATE) reads as the family it names today.
        boolean full = fields.length == FIELDS;
        return new SessionDecisionRecord(at, blank(fields[1]), blank(fields[2]), blank(fields[3]),
                ActionFamily.nameOrRaw(blank(fields[4])), blank(fields[5]), full ? blank(fields[6]) : null,
                full ? items(blank(fields[7])) : null);
    }

    /** The record as a line of facts: "2026-09-30T14:01:00Z | GET /api/x?y | READ | ALLOW". */
    public String describe() {
        String request = (method != null ? method + " " : "") + (path != null ? path : "")
                + (query != null ? "?" + query : "");
        return (at != null ? at.toString() : "-") + " | " + (request.isBlank() ? "-" : request.trim()) + " | "
                + (actionFamily != null ? actionFamily : "-") + " | " + (outcome != null ? outcome : "-");
    }

    private static String text(Object value) {
        return value != null && !value.toString().isBlank() ? value.toString() : null;
    }

    private static String field(String value) {
        return value != null ? value.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ') : "";
    }

    private static String blank(String value) {
        return value.isEmpty() ? null : value;
    }
}
