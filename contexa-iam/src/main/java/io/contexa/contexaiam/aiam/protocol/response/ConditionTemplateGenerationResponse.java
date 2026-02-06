package io.contexa.contexaiam.aiam.protocol.response;

import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.Getter;

import java.util.Map;

@Getter
public class ConditionTemplateGenerationResponse extends AIResponse {
    
    private final String templateResult; 
    private final String templateType; 
    private final String resourceIdentifier; 
    private final Map<String, Object> processingMetadata; 
    
    public ConditionTemplateGenerationResponse(String templateResult, String templateType,
                                             String resourceIdentifier, Map<String, Object> processingMetadata) {
        this.templateResult = templateResult;
        this.templateType = templateType;
        this.resourceIdentifier = resourceIdentifier;
        this.processingMetadata = processingMetadata != null ? processingMetadata : Map.of();
    }

    public static ConditionTemplateGenerationResponse success(String templateResult, String templateType, String resourceIdentifier) {
        return new ConditionTemplateGenerationResponse(
                templateResult,
                templateType,
                resourceIdentifier,
                Map.of("generatedAt", System.currentTimeMillis())
        );
    }

    public static ConditionTemplateGenerationResponse failure(String templateType,
                                                            String resourceIdentifier, String errorMessage) {
        return new ConditionTemplateGenerationResponse(
                "[]",
                templateType,
                resourceIdentifier,
                Map.of("error", errorMessage, "failedAt", System.currentTimeMillis())
        );
    }

    public boolean hasTemplates() {
        return templateResult != null && 
               !templateResult.trim().isEmpty() && 
               !templateResult.trim().equals("[]");
    }
}