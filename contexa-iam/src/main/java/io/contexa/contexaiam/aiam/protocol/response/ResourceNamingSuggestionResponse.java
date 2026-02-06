package io.contexa.contexaiam.aiam.protocol.response;

import io.contexa.contexaiam.aiam.protocol.request.ResourceNameSuggestion;
import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.*;

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