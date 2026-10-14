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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W3-14: the mapping table of the v19 labels to their v20 places, which the runtime governance rules, the rule
 * applier and the prompt quality fault injector move by, is the inventory (prompt-dictionary/v19-inventory-places.json,
 * inventory section 1) plus the two label aliases the applier accepted.
 */
class SecurityDecisionPromptLabelPlacesTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern SPECIAL_PLACE = Pattern.compile(
            "(BLOCK_HEADER|BLOCK_LINES):[A-Z_]+|BLOCK_HEADERS|SOURCE_GRADE|SYSTEM_TEXT|NO_FACT|REMOVED:Q-\\d+");

    @Test
    void theTableIsTheInventoryAndTheTwoApplierAliases() throws IOException {
        Map<String, List<String>> expected = new LinkedHashMap<>();
        for (JsonNode row : read("/prompt-dictionary/v19-inventory-places.json").path("labels")) {
            LinkedHashSet<String> places = new LinkedHashSet<>();
            row.path("places").forEach(place -> places.add(place.asText()));
            expected.put(row.path("label").asText(), List.copyOf(places));
        }
        expected.put("Method", expected.get("HttpMethod"));
        expected.put("Resource ID", expected.get("ResourceId"));

        Map<String, List<String>> table = new LinkedHashMap<>();
        for (String label : SecurityDecisionPromptLabelPlaces.labels()) {
            table.put(label, SecurityDecisionPromptLabelPlaces.placesOf(label));
        }
        assertThat(table).containsExactlyEntriesOf(expected);
    }

    @Test
    void everyPlaceIsADictionaryEntryOrOneOfTheSpecialPlaces() {
        Map<String, PromptDictionaryEntry> entries = new LinkedHashMap<>();
        SecurityDecisionPromptDictionary.ENTRIES.forEach(entry -> entries.put(entry.block().name() + "." + entry.name(), entry));
        List<String> unknown = new ArrayList<>();
        for (String label : SecurityDecisionPromptLabelPlaces.labels()) {
            for (String place : SecurityDecisionPromptLabelPlaces.placesOf(label)) {
                if (!entries.containsKey(place) && !SPECIAL_PLACE.matcher(place).matches()) {
                    unknown.add(label + " -> " + place);
                }
            }
            List<PromptDictionaryEntry> expected = SecurityDecisionPromptLabelPlaces.placesOf(label).stream()
                    .filter(entries::containsKey).map(entries::get).toList();
            assertThat(SecurityDecisionPromptLabelPlaces.entriesOf(label)).as(label).containsExactlyElementsOf(expected);
        }
        assertThat(unknown).isEmpty();
    }

    @Test
    void theLabelsTheApplierAndTheFaultInjectorUsedHaveTheirV20Places() {
        assertThat(keys("RequestPath")).containsExactly("REQUEST.Action");
        assertThat(keys("Path")).containsExactly("REQUEST.Action");
        assertThat(keys("Method")).containsExactly("REQUEST.Action");
        assertThat(keys("Resource ID")).containsExactly("REQUEST.Action");
        assertThat(keys("BusinessLabel")).containsExactly("REQUEST.Target", "REQUEST.Size");
        assertThat(keys("TenantId")).containsExactly("DECISION_FACTS.DataConflicts");
        assertThat(keys("RagDocument1")).containsExactly("PAST_RECORDS.PastRecord{i}");
        assertThat(keys("RagScopeReason")).containsExactly("PAST_RECORDS.PastRecordsState");
        assertThat(SecurityDecisionPromptLabelPlaces.placesOf("RagEvidenceBoundary")).containsExactly("SYSTEM_TEXT");
        assertThat(SecurityDecisionPromptLabelPlaces.placesOf("BaselineContextSummary"))
                .containsExactly("BLOCK_LINES:USER_BASELINE");
        assertThat(SecurityDecisionPromptLabelPlaces.singleEntryOf("HttpMethod").map(PromptDictionaryEntry::name))
                .contains("Action");
        assertThat(SecurityDecisionPromptLabelPlaces.singleEntryOf("MfaVerified")).isEmpty();
        assertThat(SecurityDecisionPromptLabelPlaces.entriesOf("MfaVerified")).extracting(PromptDictionaryEntry::name)
                .containsExactly("LoginMethod", "ChallengeVerified", "RecentMfaElsewhere");
        assertThat(SecurityDecisionPromptLabelPlaces.placesOf("NotAV19Label")).isEmpty();
        assertThat(SecurityDecisionPromptLabelPlaces.entriesOf("Action")).isEmpty();
        assertThat(SecurityDecisionPromptLabelPlaces.entriesOf("RequestPath")).allMatch(entry ->
                entry.block() == PromptBlock.REQUEST);
    }

    private static List<String> keys(String label) {
        return SecurityDecisionPromptLabelPlaces.entriesOf(label).stream()
                .map(entry -> entry.block().name() + "." + entry.name()).toList();
    }

    private static JsonNode read(String resource) throws IOException {
        try (InputStream input = SecurityDecisionPromptLabelPlacesTest.class.getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            return JSON.readTree(input);
        }
    }
}
