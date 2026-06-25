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
package io.contexa.contexaiam.aiam.protocol.response;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ResourceNamingSuggestionResponse parsing")
class ResourceNamingSuggestionResponseTest {

    @Test
    @DisplayName("Identifier-keyed JSON parses into resource suggestions")
    void fromMap_parsesIdentifierKeyedJson() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("/contexa/admin/users", Map.of(
                "friendlyName", "User Management",
                "description", "Manage user accounts.",
                "confidence", 0.91
        ));

        ResourceNamingSuggestionResponse response = ResourceNamingSuggestionResponse.fromMap(payload);

        assertThat(response.getFailedIdentifiers()).isEmpty();
        assertThat(response.getSuggestions()).hasSize(1);
        ResourceNamingSuggestionResponse.ResourceNamingSuggestion suggestion = response.getSuggestions().get(0);
        assertThat(suggestion.getIdentifier()).isEqualTo("/contexa/admin/users");
        assertThat(suggestion.getFriendlyName()).isEqualTo("User Management");
        assertThat(suggestion.getDescription()).isEqualTo("Manage user accounts.");
        assertThat(suggestion.getConfidence()).isEqualTo(0.91);
    }

    @Test
    @DisplayName("Protocol metadata such as stats must not become resource suggestions")
    void fromMap_ignoresStatsMetadata() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("stats", Map.of("itemCount", 1));

        ResourceNamingSuggestionResponse response = ResourceNamingSuggestionResponse.fromMap(payload);

        assertThat(response.getSuggestions()).isEmpty();
        assertThat(response.toResourceNameSuggestionMap()).doesNotContainKey("stats");
    }

    @Test
    @DisplayName("Missing friendlyName or description is treated as failed, not as fallback success")
    void fromMap_missingFieldsBecomeFailedIdentifiers() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("/api/stats", Map.of("friendlyName", "Stats"));

        ResourceNamingSuggestionResponse response = ResourceNamingSuggestionResponse.fromMap(payload);

        assertThat(response.getSuggestions()).isEmpty();
        assertThat(response.getFailedIdentifiers()).containsExactly("/api/stats");
    }

    @Test
    @DisplayName("Legacy suggestions array is parsed safely for backward compatibility")
    void fromMap_parsesLegacySuggestionsArray() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("suggestions", List.of(Map.of(
                "identifier", "/api/groups",
                "friendlyName", "Group API",
                "description", "Manage groups.",
                "confidence", "0.77"
        )));
        payload.put("stats", Map.of("itemCount", 1));

        ResourceNamingSuggestionResponse response = ResourceNamingSuggestionResponse.fromMap(payload);

        assertThat(response.getFailedIdentifiers()).isEmpty();
        assertThat(response.getSuggestions()).hasSize(1);
        assertThat(response.getSuggestions().get(0).getIdentifier()).isEqualTo("/api/groups");
        assertThat(response.getSuggestions().get(0).getConfidence()).isEqualTo(0.77);
    }
}