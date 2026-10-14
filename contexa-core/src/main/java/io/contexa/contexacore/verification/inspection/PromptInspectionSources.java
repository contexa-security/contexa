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
package io.contexa.contexacore.verification.inspection;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedPastRecordSummary;
import org.springframework.ai.document.Document;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The sealed sources the checks compare with besides the canonical context, read once for every check (R1b-4): the
 * request facts, the authentication state and the past records the search returned, with the names of the sources that
 * were sealed but do not read (an unreadable source is left empty here and named, never read again by a check).
 */
public record PromptInspectionSources(
        Map<String, Object> requestFacts,
        Map<String, Object> authState,
        List<Document> pastRecords,
        Set<String> unread) {

    public static final String REQUEST_FACTS = "requestFactsJson";
    public static final String AUTH_STATE = "authStateJson";
    public static final String PAST_RECORDS = "ragResultsJson";

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    public PromptInspectionSources {
        requestFacts = Collections.unmodifiableMap(new LinkedHashMap<>(requestFacts));
        authState = Collections.unmodifiableMap(new LinkedHashMap<>(authState));
        pastRecords = List.copyOf(pastRecords);
        unread = Collections.unmodifiableSet(new LinkedHashSet<>(unread));
    }

    public static PromptInspectionSources read(SealedEvidencePackage evidencePackage) {
        Set<String> unread = new LinkedHashSet<>();
        Map<String, Object> requestFacts = map(evidencePackage.getRequestFactsJson(), REQUEST_FACTS, unread);
        Map<String, Object> authState = map(evidencePackage.getAuthStateJson(), AUTH_STATE, unread);
        String pastRecords = evidencePackage.getRagResultsJson();
        map(pastRecords, PAST_RECORDS, unread);
        List<Document> records = unread.contains(PAST_RECORDS) ? List.of() : SealedPastRecordSummary.records(pastRecords);
        return new PromptInspectionSources(requestFacts, authState, records, unread);
    }

    /** A sealed JSON object; an absent one is empty, one that does not read is empty and named. */
    private static Map<String, Object> map(String json, String source, Set<String> unread) {
        if (!hasText(json)) {
            return Map.of();
        }
        try {
            Map<String, Object> map = JSON.readValue(json, MAP);
            return map == null ? Map.of() : map;
        }
        catch (Exception exception) {
            // A source changed after sealing also shows in the package hash; here it is only named as not read.
            unread.add(source);
            return Map.of();
        }
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
