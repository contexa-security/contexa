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

import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNameSuggestion;
import lombok.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Setter
@NoArgsConstructor
public class ResourceNamingSuggestionResponse extends AIResponse {

    private static final Set<String> PROTOCOL_METADATA_KEYS = Set.of(
            "suggestions", "stats", "failedIdentifiers", "summary", "metadata"
    );
    private static final double DEFAULT_CONFIDENCE = 0.8;

    private List<ResourceNamingSuggestion> suggestions;
    private List<String> failedIdentifiers;

    public ResourceNamingSuggestionResponse(List<ResourceNamingSuggestion> suggestions,
                                          List<String> failedIdentifiers) {
        this.suggestions = suggestions != null ? suggestions : List.of();
        this.failedIdentifiers = failedIdentifiers != null ? failedIdentifiers : List.of();
    }

    public List<ResourceNamingSuggestion> getSuggestions() {
        return suggestions != null ? suggestions : List.of();
    }

    public List<String> getFailedIdentifiers() {
        return failedIdentifiers != null ? failedIdentifiers : List.of();
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
                    .confidence(DEFAULT_CONFIDENCE)
                    .build();
        }
    }

    public Map<String, ResourceNameSuggestion> toResourceNameSuggestionMap() {
        return getSuggestions().stream()
                .filter(suggestion -> hasText(suggestion.getIdentifier()))
                .collect(Collectors.toMap(
                        ResourceNamingSuggestion::getIdentifier,
                        ResourceNamingSuggestion::toResourceNameSuggestion,
                        (first, ignored) -> first,
                        LinkedHashMap::new
                ));
    }

    public static ResourceNamingSuggestionResponse fromMap(Map<String, Object> mapResponse) {
        if (mapResponse == null || mapResponse.isEmpty()) {
            return new ResourceNamingSuggestionResponse(List.of(), List.of());
        }

        if (mapResponse.get("suggestions") instanceof List<?> suggestionsArray) {
            return fromSuggestionArray(suggestionsArray, mapResponse.get("failedIdentifiers"));
        }

        List<String> failedIdentifiers = new ArrayList<>();
        List<ResourceNamingSuggestion> suggestions = new ArrayList<>();

        for (Map.Entry<String, Object> entry : mapResponse.entrySet()) {
            String identifier = entry.getKey();
            if (PROTOCOL_METADATA_KEYS.contains(identifier)) {
                continue;
            }
            ResourceNamingSuggestion suggestion = parseSuggestion(identifier, entry.getValue(), failedIdentifiers);
            if (suggestion != null) {
                suggestions.add(suggestion);
            }
        }
        return new ResourceNamingSuggestionResponse(suggestions, failedIdentifiers);
    }

    private static ResourceNamingSuggestionResponse fromSuggestionArray(List<?> suggestionsArray, Object failedIdentifiersValue) {
        List<String> failedIdentifiers = new ArrayList<>();
        failedIdentifiers.addAll(parseFailedIdentifiers(failedIdentifiersValue));
        List<ResourceNamingSuggestion> suggestions = new ArrayList<>();

        for (Object rawSuggestion : suggestionsArray) {
            if (!(rawSuggestion instanceof Map<?, ?> suggestionMap)) {
                continue;
            }
            String identifier = textValue(suggestionMap.get("identifier"));
            ResourceNamingSuggestion suggestion = parseSuggestion(identifier, suggestionMap, failedIdentifiers);
            if (suggestion != null) {
                suggestions.add(suggestion);
            }
        }
        return new ResourceNamingSuggestionResponse(suggestions, failedIdentifiers);
    }

    private static ResourceNamingSuggestion parseSuggestion(String identifier, Object rawValue, List<String> failedIdentifiers) {
        if (!hasText(identifier)) {
            return null;
        }
        if (!(rawValue instanceof Map<?, ?> value)) {
            failedIdentifiers.add(identifier);
            return null;
        }

        String friendlyName = textValue(value.get("friendlyName"));
        String description = textValue(value.get("description"));
        if (!hasText(friendlyName) || !hasText(description)) {
            failedIdentifiers.add(identifier);
            return null;
        }

        return ResourceNamingSuggestion.builder()
                .identifier(identifier)
                .friendlyName(friendlyName)
                .description(description)
                .confidence(parseConfidence(value.get("confidence")))
                .build();
    }

    private static List<String> parseFailedIdentifiers(Object failedIdentifiersValue) {
        if (!(failedIdentifiersValue instanceof List<?> values)) {
            return List.of();
        }
        return values.stream()
                .map(ResourceNamingSuggestionResponse::textValue)
                .filter(ResourceNamingSuggestionResponse::hasText)
                .toList();
    }

    private static double parseConfidence(Object rawConfidence) {
        if (rawConfidence instanceof Number number) {
            return clampConfidence(number.doubleValue());
        }
        if (rawConfidence instanceof String text && hasText(text)) {
            try {
                return clampConfidence(Double.parseDouble(text));
            } catch (NumberFormatException ignored) {
                return DEFAULT_CONFIDENCE;
            }
        }
        return DEFAULT_CONFIDENCE;
    }

    private static double clampConfidence(double confidence) {
        if (Double.isNaN(confidence)) {
            return DEFAULT_CONFIDENCE;
        }
        return Math.max(0.0, Math.min(1.0, confidence));
    }

    private static String textValue(Object value) {
        return value instanceof String text ? text.trim() : null;
    }

    private static boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }

    public static ResourceNamingSuggestionResponse fromResourceNameSuggestionMap(Map<String, ResourceNameSuggestion> suggestionMap) {
        List<ResourceNamingSuggestion> suggestions = suggestionMap.entrySet().stream()
                .map(entry -> ResourceNamingSuggestion.fromResourceNameSuggestion(entry.getKey(), entry.getValue()))
                .toList();

        return new ResourceNamingSuggestionResponse(suggestions, List.of());
    }
}
