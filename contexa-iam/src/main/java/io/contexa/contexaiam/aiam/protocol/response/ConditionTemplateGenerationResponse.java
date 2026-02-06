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
    
    public ConditionTemplateGenerationResponse(String requestId, ExecutionStatus status,
                                             String templateResult, String templateType,
                                             String resourceIdentifier, Map<String, Object> processingMetadata) {
        super(requestId, status);
        this.templateResult = templateResult;
        this.templateType = templateType;
        this.resourceIdentifier = resourceIdentifier;
        this.processingMetadata = processingMetadata != null ? processingMetadata : Map.of();
    }

    public static ConditionTemplateGenerationResponse success(String requestId, String templateResult, 
                                                            String templateType, String resourceIdentifier) {
        return new ConditionTemplateGenerationResponse(
                requestId, 
                ExecutionStatus.SUCCESS,
                templateResult, 
                templateType,
                resourceIdentifier,
                Map.of("generatedAt", System.currentTimeMillis())
        );
    }

    public static ConditionTemplateGenerationResponse failure(String requestId, String templateType, 
                                                            String resourceIdentifier, String errorMessage) {
        return new ConditionTemplateGenerationResponse(
                requestId, 
                ExecutionStatus.FAILURE,
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