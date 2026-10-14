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
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The v19 labels of the security decision user prompt and their v20 places (W3-14): the place of every v19 label from
 * inventory section 1, and the two label aliases the runtime governance rule applier accepted. A place is a dictionary
 * entry ({@code BLOCK.Entry}, the block's enum name) or a place without an entry: {@code NO_FACT}, {@code SYSTEM_TEXT},
 * {@code SOURCE_GRADE}, {@code BLOCK_HEADERS}, {@code BLOCK_HEADER:<block>}, {@code BLOCK_LINES:<block>} or
 * {@code REMOVED:<decision>} (a fact the user removed under principle 14, W3-5). The runtime
 * governance rules, the rule applier and the prompt quality fault injector move their v19 labels to the v20 dictionary
 * names by this table.
 */
public final class SecurityDecisionPromptLabelPlaces {

    private static final String RESOURCE = "/prompt-dictionary/v19-label-places.json";
    private static final Map<String, List<String>> PLACES = load();
    private static final Map<String, PromptDictionaryEntry> ENTRIES = entries();

    private SecurityDecisionPromptLabelPlaces() {
    }

    /** The v19 labels of the table, in its order. */
    public static List<String> labels() {
        return List.copyOf(PLACES.keySet());
    }

    /** The v20 places of a v19 label; nothing for a label the table does not hold. */
    public static List<String> placesOf(String label) {
        return label == null ? List.of() : PLACES.getOrDefault(label, List.of());
    }

    /** The dictionary entries among the v20 places of a v19 label. */
    public static List<PromptDictionaryEntry> entriesOf(String label) {
        return placesOf(label).stream().map(ENTRIES::get).filter(Objects::nonNull).toList();
    }

    /** The dictionary entry of a v19 label whose facts went to exactly one entry. */
    public static Optional<PromptDictionaryEntry> singleEntryOf(String label) {
        List<PromptDictionaryEntry> entries = entriesOf(label);
        return entries.size() == 1 ? Optional.of(entries.get(0)) : Optional.empty();
    }

    private static Map<String, List<String>> load() {
        try (InputStream input = SecurityDecisionPromptLabelPlaces.class.getResourceAsStream(RESOURCE)) {
            if (input == null) {
                throw new IllegalStateException("Label place table is missing: " + RESOURCE);
            }
            JsonNode root = new ObjectMapper().readTree(input);
            Map<String, List<String>> places = new LinkedHashMap<>();
            for (JsonNode row : root.path("labels")) {
                List<String> rowPlaces = new ArrayList<>();
                row.path("places").forEach(place -> rowPlaces.add(place.asText()));
                places.put(row.path("label").asText(), List.copyOf(rowPlaces));
            }
            return Collections.unmodifiableMap(places);
        }
        catch (IOException exception) {
            throw new UncheckedIOException("Label place table is unreadable: " + RESOURCE, exception);
        }
    }

    private static Map<String, PromptDictionaryEntry> entries() {
        Map<String, PromptDictionaryEntry> entries = new LinkedHashMap<>();
        for (PromptDictionaryEntry entry : SecurityDecisionPromptDictionary.ENTRIES) {
            entries.put(entry.block().name() + "." + entry.name(), entry);
        }
        return Collections.unmodifiableMap(entries);
    }
}
