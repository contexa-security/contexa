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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.decision.RelativeTime;
import io.contexa.contexacore.autonomous.context.prompt.PromptListItem;
import io.contexa.contexacore.autonomous.context.support.PastRecordRanking;
import io.contexa.contexacore.autonomous.context.support.PastRecordRelevance;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.TextStyle;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.BiFunction;

/**
 * The past records of the v20 PAST RECORDS block (W3-3, dictionary 7): one line of twelve fields per record,
 * {@code date day time / action / path template / target / items / class / network / device / login / decision /
 * same target / authorized as}. A value the record does not hold is said to be not recorded. Records of the same facts
 * (every field but the time) are one line with their count and the latest time. A similarity is not a field: it
 * decides nothing (W3-18); a tie in the line order goes to the stored ID of the line's latest record. The audit
 * metadata and the document text stay in the sealed record, which keeps every document field.
 */
final class PastRecordLines {

    /** The time field of a line whose records hold no time. */
    static final String TIME_NOT_RECORDED = "time not recorded";


    private PastRecordLines() {
    }

    static List<PromptListItem> items(List<Document> documents, PastRecordRelevance.Subject request) {
        return items(documents, request, null);
    }

    /**
     * The lines of the records; with the request's time on the event clock, each line's latest time also says how long
     * before the request it was (W3-13).
     */
    static List<PromptListItem> items(List<Document> documents, PastRecordRelevance.Subject request,
                                      LocalDateTime requestTime) {
        return items(documents, (document, record) -> request != null
                ? PastRecordRelevance.sameTarget(request, record)
                : PastRecordRelevance.NOT_KNOWN, requestTime);
    }

    /**
     * The lines of the records with the same-target field each record is given (the render reads it from the request;
     * the prompt inspector reads the one sealed with the record).
     */
    static List<PromptListItem> items(List<Document> documents,
                                      BiFunction<Document, PastRecordRelevance.Subject, String> sameTargetOf,
                                      LocalDateTime requestTime) {
        Map<String, Group> groups = new LinkedHashMap<>();
        if (documents != null) {
            for (Document document : documents) {
                if (document == null) {
                    continue;
                }
                Map<String, Object> metadata = document.getMetadata() != null ? document.getMetadata() : Map.of();
                // The path template, the target and the same-target field come from one reading of the record.
                PastRecordRelevance.Subject record = PastRecordRelevance.Subject.ofRecord(metadata, document.getText());
                String sameTarget = sameTargetOf.apply(document, record);
                List<String> facts = facts(metadata, record, sameTarget);
                groups.computeIfAbsent(String.join(PastRecordLineValues.SEPARATOR, facts), key -> new Group(facts, sameTarget))
                        .add(PastRecordRanking.recordedAtOrNull(metadata), PastRecordRanking.storedId(document));
            }
        }
        List<PromptListItem> items = new ArrayList<>();
        for (Group group : groups.values()) {
            items.add(group.item(requestTime));
        }
        return List.copyOf(items);
    }

    /** The fields of a record other than the time, in line order with the same-target field. */
    private static List<String> facts(Map<String, Object> metadata, PastRecordRelevance.Subject record,
                                      String sameTarget) {
        List<String> facts = new ArrayList<>();
        facts.add(orNotRecorded(text(metadata.get("actionFamily")), "action"));
        facts.add(orNotRecorded(record.pathFamily(), "path"));
        facts.add(record.target() != null ? record.target() : "no target");
        facts.add(metadata.get("requestItems") instanceof Number items
                ? String.format(Locale.ROOT, "%,d items", items.longValue()) : "items not recorded");
        String resourceClass = text(metadata.get("resourceFamily"));
        facts.add(resourceClass != null ? "class " + resourceClass : "class not recorded");
        facts.add(network(metadata));
        String device = SecuritySemanticNormalizer.device(
                firstText(text(metadata.get("userAgentBrowser")), text(metadata.get("deviceBrowser"))),
                firstText(text(metadata.get("userAgentOS")), text(metadata.get("deviceOs"))));
        facts.add(device != null ? device : "device not recorded");
        String login = text(metadata.get("authenticationType"));
        facts.add(login != null ? login + " login" : "login not recorded");
        facts.add(decision(firstText(text(metadata.get("autonomousAction")), text(metadata.get("action")))));
        facts.add(PastRecordLineValues.SAME_TARGET + sameTarget);
        facts.add(authorizedAs(metadata));
        return facts;
    }

    private static String network(Map<String, Object> metadata) {
        String band = text(metadata.get("ipBand"));
        if (band == null) {
            return "network not recorded";
        }
        String zone = text(metadata.get("networkZone"));
        return band + " zone " + (zone != null ? zone : "not recorded");
    }

    private static String decision(String action) {
        if (action == null) {
            return "decision not recorded";
        }
        return switch (action.toUpperCase(Locale.ROOT)) {
            case "ALLOW" -> "allowed";
            case "CHALLENGE" -> "challenged";
            case "ESCALATE" -> "escalated";
            case "BLOCK" -> "blocked";
            default -> action.toLowerCase(Locale.ROOT);
        };
    }

    private static String authorizedAs(Map<String, Object> metadata) {
        String decision = text(metadata.get(VectorDocumentMetadata.AUTHORIZATION_DECISION));
        if (decision == null) {
            return "authorized as not recorded";
        }
        List<String> details = new ArrayList<>();
        String scope = text(metadata.get(VectorDocumentMetadata.ACCESS_SCOPE));
        if (scope != null) {
            details.add("scope " + scope);
        }
        if ("true".equalsIgnoreCase(text(metadata.get(VectorDocumentMetadata.TENANT_BOUND)))) {
            details.add("tenant bound");
        }
        if ("true".equalsIgnoreCase(text(metadata.get(VectorDocumentMetadata.PURPOSE_MATCH)))) {
            details.add("purpose match");
        }
        return "authorized as " + decision + (details.isEmpty() ? "" : " (" + String.join(", ", details) + ")");
    }

    private static String orNotRecorded(String value, String name) {
        return value != null ? value : name + " not recorded";
    }

    private static String text(Object value) {
        return value != null && StringUtils.hasText(value.toString()) ? value.toString().trim() : null;
    }

    private static String firstText(String first, String second) {
        return first != null ? first : second;
    }

    /** The records of one set of facts: their count, the latest time and that record's stored ID. */
    private static final class Group {

        private final List<String> facts;
        private final String sameTarget;
        private int count;
        private LocalDateTime latest;
        private String id;

        private Group(List<String> facts, String sameTarget) {
            this.facts = facts;
            this.sameTarget = sameTarget;
        }

        private void add(LocalDateTime at, String recordId) {
            count++;
            if (count == 1 || (at != null && (latest == null || at.isAfter(latest)))) {
                latest = at;
                id = recordId;
            }
        }

        private PromptListItem item(LocalDateTime requestTime) {
            String relative = RelativeTime.of(latest, requestTime);
            String time = latest == null ? TIME_NOT_RECORDED
                    : String.format(Locale.ROOT, PastRecordLineValues.TIME_FORMAT, latest.getMonthValue(), latest.getDayOfMonth(),
                    latest.getDayOfWeek().getDisplayName(TextStyle.SHORT, Locale.ROOT), latest.getHour(), latest.getMinute())
                    + (relative != null ? " (" + relative + ")" : "");
            List<String> fields = new ArrayList<>();
            fields.add(time + (count > 1 ? PastRecordLineValues.REPEAT + count : ""));
            fields.addAll(facts);
            return PromptListItem.pastRecord(String.join(PastRecordLineValues.SEPARATOR, fields), PastRecordRelevance.YES.equals(sameTarget),
                    latest != null ? latest.toEpochSecond(ZoneOffset.UTC) * 1000L : 0L, id);
        }
    }
}
