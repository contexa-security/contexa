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
                        .friendlyName(friendlyName != null ? friendlyName : identifier + " 기능")
                        .description(description != null ? description : "AI 추천을 받지 못한 리소스입니다.")
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