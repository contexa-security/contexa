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
package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import org.springframework.ai.document.Document;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A past record as the sealed package keeps it ({@code ragResultsJson.relatedDocuments}): written by the assembler from
 * the record the render read, and read back into that record for the prompt inspector (R1b-3: the one place of the
 * summary's keys).
 */
public final class SealedPastRecordSummary {

    /** The summary keys the record keeps under another name, mapped back to the metadata keys the render read. */
    private static final Map<String, String> SUMMARY_KEYS = Map.of(
            "authorization", VectorDocumentMetadata.AUTHORIZATION_DECISION,
            "purpose", VectorDocumentMetadata.PURPOSE_MATCH,
            "retrievalPolicy", VectorDocumentMetadata.RETRIEVAL_POLICY_SUMMARY);
    /**
     * The record metadata keys the summary keeps: the audit fields, and every key a past record line reads (the path,
     * path template, method and target keys of PastRecordRelevance, the line fields of PastRecordLines, the time, ids and
     * scores of PastRecordRanking), and the hour and day of week the baseline comparison reads of the record (the
     * closest past record of the learning evidence, N-SEAL-1).
     */
    private static final List<String> KEPT_KEYS = List.of(VectorDocumentMetadata.ID, VectorDocumentMetadata.TIMESTAMP,
            VectorDocumentMetadata.EVENT_ID, "documentType", "userId", "tenantId", "organizationId", "resourceId",
            "requestPath", "resourcePath", "path", "pathFamily", "requestPathFamily", "httpMethod", "resourceFamily",
            VectorDocumentMetadata.AUTHORIZATION_DECISION, VectorDocumentMetadata.PURPOSE_MATCH,
            VectorDocumentMetadata.TENANT_BOUND, "retrievalPurpose", VectorDocumentMetadata.RETRIEVAL_POLICY_SUMMARY,
            VectorDocumentMetadata.ACCESS_SCOPE, "action", "actionFamily", "requestItems", "ipBand", "networkZone",
            "userAgentBrowser", "userAgentOS", "deviceBrowser", "deviceOs", "authenticationType", "autonomousAction",
            "hour", "dayOfWeek", VectorDocumentMetadata.SIMILARITY_SCORE, "distance");
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    private SealedPastRecordSummary() {
    }

    /**
     * The summary the sealed package keeps of a past record the render read. The fields a past record line draws are kept
     * as the record holds them, with no fallback or derived value, so that the record read back draws the line the render
     * drew (R1b-3, P3 extra 38: a fallback authorization, a class from the sensitivity and a derived path template made the
     * read-back record draw other fields).
     */
    public static Map<String, Object> of(Document document) {
        Map<String, Object> summary = new LinkedHashMap<>();
        if (document == null) {
            return summary;
        }
        Map<String, Object> metadata = document.getMetadata();
        if (metadata != null) {
            for (String key : KEPT_KEYS) {
                putIfPresent(summary, summaryName(key), metadata.get(key));
            }
        }
        putIfPresent(summary, "score", document.getScore());
        String text = document.getText();
        if (hasText(text)) {
            summary.put("textPreview", text.length() > 240 ? text.substring(0, 240) : text);
            summary.put("textLength", text.length());
        }
        return summary;
    }

    /** The name a metadata key is kept under in the summary. */
    private static String summaryName(String key) {
        for (Map.Entry<String, String> renamed : SUMMARY_KEYS.entrySet()) {
            if (renamed.getValue().equals(key)) {
                return renamed.getKey();
            }
        }
        return key;
    }

    /**
     * The past records a sealed retrieval summary keeps, read back as the render read them: the renamed keys under
     * their metadata names, the text preview as the text (the inspector draws the lines from them).
     */
    public static List<Document> records(String ragResultsJson) {
        List<Document> documents = new ArrayList<>();
        Object related = read(ragResultsJson).get("relatedDocuments");
        if (!(related instanceof List<?> summaries)) {
            return documents;
        }
        for (Object item : summaries) {
            if (!(item instanceof Map<?, ?> summary)) {
                continue;
            }
            Map<String, Object> recordMetadata = new LinkedHashMap<>();
            summary.forEach((key, value) -> {
                String name = String.valueOf(key);
                if (!"textPreview".equals(name) && !"textLength".equals(name) && !"score".equals(name) && value != null) {
                    recordMetadata.put(SUMMARY_KEYS.getOrDefault(name, name), value);
                }
            });
            Object preview = summary.get("textPreview");
            Object score = summary.get("score");
            documents.add(Document.builder()
                    .id(String.valueOf(summary.get("id")))
                    .text(preview != null && !preview.toString().isBlank() ? preview.toString() : " ")
                    .metadata(recordMetadata)
                    .score(score instanceof Number number ? number.doubleValue() : null)
                    .build());
        }
        return documents;
    }

    private static Map<String, Object> read(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            Map<String, Object> map = JSON.readValue(json, MAP);
            return map == null ? Map.of() : map;
        }
        catch (Exception exception) {
            // An unreadable retrieval summary gives no records; the package hash shows a change after sealing.
            return Map.of();
        }
    }

    private static void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (value == null) {
            return;
        }
        if (value instanceof String text && text.isBlank()) {
            return;
        }
        target.put(key, value);
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
