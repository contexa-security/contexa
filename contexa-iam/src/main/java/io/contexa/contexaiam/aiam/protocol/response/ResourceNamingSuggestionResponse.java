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

import io.contexa.contexaiam.aiam.protocol.request.ResourceNameSuggestion;
import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
public class ResourceNamingSuggestionResponse extends AIResponse {

    private List<ResourceNamingSuggestion> suggestions;
    private List<String> failedIdentifiers;

    public ResourceNamingSuggestionResponse(List<ResourceNamingSuggestion> suggestions,
                                          List<String> failedIdentifiers) {
        this.suggestions = suggestions != null ? suggestions : List.of();
        this.failedIdentifiers = failedIdentifiers != null ? failedIdentifiers : List.of();
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ResourceNamingSuggestion {

        private String identifier;
        private String friendlyName;
        private String description;
        private double confidence;

        public ResourceNameSuggestion toResourceNameSuggestion() {
            return new ResourceNameSuggestion(friendlyName, description);
        }

        public static ResourceNamingSuggestion fromResourceNameSuggestion(String identifier, ResourceNameSuggestion suggestion) {
            return ResourceNamingSuggestion.builder()
                    .identifier(identifier)
                    .friendlyName(suggestion.friendlyName())
                    .description(suggestion.description())
                    .confidence(0.8)
                    .build();
        }
    }

    public Map<String, ResourceNameSuggestion> toResourceNameSuggestionMap() {
        return suggestions.stream()
                .collect(Collectors.toMap(
                        ResourceNamingSuggestion::getIdentifier,
                        ResourceNamingSuggestion::toResourceNameSuggestion
                ));
    }

    public static ResourceNamingSuggestionResponse fromMap(Map<String, Object> mapResponse) {
        List<String> failedIdentifiers = new ArrayList<>();
        List<ResourceNamingSuggestion> suggestions = new ArrayList<>();

        for (Map.Entry<String, Object> entry : mapResponse.entrySet()) {
            String identifier = entry.getKey();
            try {
                Map<String, String> value = (Map<String, String>) entry.getValue();
                String friendlyName = value.get("friendlyName");
                String description = value.get("description");

                suggestions.add(ResourceNamingSuggestion.builder()
                        .identifier(identifier)
                        .friendlyName(friendlyName != null ? friendlyName : identifier + " feature")
                        .description(description != null ? description : "Resource that did not receive AI recommendation.")
                        .confidence(0.8)
                        .build());
            } catch (Exception e) {
                failedIdentifiers.add(identifier);
            }
        }
        return new ResourceNamingSuggestionResponse(suggestions, failedIdentifiers);
    }

    public static ResourceNamingSuggestionResponse fromResourceNameSuggestionMap(Map<String, ResourceNameSuggestion> suggestionMap) {
        List<ResourceNamingSuggestion> suggestions = suggestionMap.entrySet().stream()
                .map(entry -> ResourceNamingSuggestion.fromResourceNameSuggestion(entry.getKey(), entry.getValue()))
                .toList();

        return new ResourceNamingSuggestionResponse(suggestions, List.of());
    }
}
