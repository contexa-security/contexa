package io.contexa.contexaiam.aiam.protocol.response;

import io.contexa.contexaiam.aiam.protocol.request.ResourceNameSuggestion;
import io.contexa.contexacommon.domain.response.IAMResponse;
import lombok.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 리소스 네이밍 AI 진단 응답 DTO
 */
@Getter
@Setter
public class ResourceNamingSuggestionResponse extends IAMResponse {

    /**
     * 성공적으로 처리된 리소스 네이밍 제안들
     */
    private List<ResourceNamingSuggestion> suggestions;
    
    /**
     * 처리 실패한 리소스 식별자들
     */
    private List<String> failedIdentifiers;
    
    /**
     * 전체 처리 통계
     */
    private ProcessingStats stats;
    
    // 기본 생성자
    public ResourceNamingSuggestionResponse() {
        super("resource-naming-default", ExecutionStatus.SUCCESS);
        this.suggestions = List.of();
        this.failedIdentifiers = List.of();
        this.stats = new ProcessingStats();
    }
    
    // 전체 생성자
    public ResourceNamingSuggestionResponse(String requestId, List<ResourceNamingSuggestion> suggestions, 
                                          List<String> failedIdentifiers, ProcessingStats stats) {
        super(requestId, ExecutionStatus.SUCCESS);
        this.suggestions = suggestions != null ? suggestions : List.of();
        this.failedIdentifiers = failedIdentifiers != null ? failedIdentifiers : List.of();
        this.stats = stats != null ? stats : new ProcessingStats();
    }
    
    @Override
    public String getResponseType() {
        return "RESOURCE_NAMING_SUGGESTION";
    }
    
    @Override
    public Object getData() {
        return Map.of(
            "suggestions", suggestions,
            "failedIdentifiers", failedIdentifiers,
            "stats", stats,
            "timestamp", getTimestamp()
        );
    }

    /**
     * 개별 리소스 네이밍 제안
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ResourceNamingSuggestion {
        /**
         * 원본 기술적 식별자
         */
        private String identifier;
        
        /**
         * AI가 제안한 친화적 이름
         */
        private String friendlyName;
        
        /**
         * AI가 제안한 상세 설명
         */
        private String description;
        
        /**
         * AI 신뢰도 점수 (0.0 ~ 1.0)
         */
        private double confidence;
        
        /**
         * ResourceNameSuggestion 으로 변환
         */
        public ResourceNameSuggestion toResourceNameSuggestion() {
            return new ResourceNameSuggestion(friendlyName, description);
        }
        
        /**
         * ResourceNameSuggestion 에서 변환
         */
        public static ResourceNamingSuggestion fromResourceNameSuggestion(String identifier, ResourceNameSuggestion suggestion) {
            return ResourceNamingSuggestion.builder()
                    .identifier(identifier)
                    .friendlyName(suggestion.friendlyName())
                    .description(suggestion.description())
                    .confidence(0.8) // 기본 신뢰도
                    .build();
        }
    }
    
    /**
     * 처리 통계
     */
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
    
    /**
     * Map<String, ResourceNameSuggestion> 형식으로 변환
     */
    public Map<String, ResourceNameSuggestion> toResourceNameSuggestionMap() {
        return suggestions.stream()
                .collect(Collectors.toMap(
                        ResourceNamingSuggestion::getIdentifier,
                        ResourceNamingSuggestion::toResourceNameSuggestion
                ));
    }
    
    /**
     * Map<String, ResourceNameSuggestion>에서 변환하는 팩토리 메서드
     */
    public static ResourceNamingSuggestionResponse fromResourceNameSuggestionMap(Map<String, ResourceNameSuggestion> suggestionMap) {
        List<ResourceNamingSuggestion> suggestions = suggestionMap.entrySet().stream()
                .map(entry -> ResourceNamingSuggestion.fromResourceNameSuggestion(entry.getKey(), entry.getValue()))
                .toList();
                
        ProcessingStats stats = ProcessingStats.builder()
                .totalRequested(suggestionMap.size())
                .successfullyProcessed(suggestionMap.size())
                .failed(0)
                .build();
                
        return new ResourceNamingSuggestionResponse("fromMap", suggestions, List.of(), stats);
    }
} 