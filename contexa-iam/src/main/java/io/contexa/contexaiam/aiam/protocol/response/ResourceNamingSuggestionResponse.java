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

    private ProcessingStats stats;

    public ResourceNamingSuggestionResponse(List<ResourceNamingSuggestion> suggestions,
                                          List<String> failedIdentifiers, ProcessingStats stats) {
        this.suggestions = suggestions != null ? suggestions : List.of();
        this.failedIdentifiers = failedIdentifiers != null ? failedIdentifiers : List.of();
        this.stats = stats != null ? stats : new ProcessingStats();
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

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ProcessingStats {
        private int totalRequested;
        private int successfullyProcessed;
        private int failed;
        private long processingTimeMs;
        
        public double getSuccessRate() {
            return totalRequested > 0 ? (double) successfullyProcessed / totalRequested : 0.0;
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

        ProcessingStats stats = ProcessingStats.builder()
                .totalRequested(mapResponse.size())
                .successfullyProcessed(suggestions.size())
                .failed(failedIdentifiers.size())
                .build();

        return new ResourceNamingSuggestionResponse(suggestions, failedIdentifiers, stats);
    }

    public static ResourceNamingSuggestionResponse fromResourceNameSuggestionMap(Map<String, ResourceNameSuggestion> suggestionMap) {
        List<ResourceNamingSuggestion> suggestions = suggestionMap.entrySet().stream()
                .map(entry -> ResourceNamingSuggestion.fromResourceNameSuggestion(entry.getKey(), entry.getValue()))
                .toList();
                
        ProcessingStats stats = ProcessingStats.builder()
                .totalRequested(suggestionMap.size())
                .successfullyProcessed(suggestionMap.size())
                .failed(0)
                .build();
                
        return new ResourceNamingSuggestionResponse(suggestions, List.of(), stats);
    }
} 