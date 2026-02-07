package io.contexa.contexaiam.aiam.protocol.response;

import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Getter
public class ConditionTemplateGenerationResponse extends AIResponse {

    private final String templateResult;
    private final String templateType;
    private final String resourceIdentifier;
    private final Map<String, Object> processingMetadata;
    private final Map<String, ConditionTemplateItem> batchResults;
    private final List<String> failedIdentifiers;

    public ConditionTemplateGenerationResponse(String templateResult, String templateType,
                                             String resourceIdentifier, Map<String, Object> processingMetadata) {
        this(templateResult, templateType, resourceIdentifier, processingMetadata, null, null);
    }

    public ConditionTemplateGenerationResponse(String templateResult, String templateType,
                                             String resourceIdentifier, Map<String, Object> processingMetadata,
                                             Map<String, ConditionTemplateItem> batchResults,
                                             List<String> failedIdentifiers) {
        this.templateResult = templateResult;
        this.templateType = templateType;
        this.resourceIdentifier = resourceIdentifier;
        this.processingMetadata = processingMetadata != null ? processingMetadata : Map.of();
        this.batchResults = batchResults;
        this.failedIdentifiers = failedIdentifiers;
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
        if (templateResult != null &&
               !templateResult.trim().isEmpty() &&
               !templateResult.trim().equals("[]")) {
            return true;
        }
        return batchResults != null && !batchResults.isEmpty();
    }

    public Map<String, ConditionTemplateItem> toConditionTemplateMap() {
        return batchResults != null ? batchResults : Map.of();
    }

    @SuppressWarnings("unchecked")
    public static ConditionTemplateGenerationResponse fromMap(Map<String, Object> mapResponse) {
        Map<String, ConditionTemplateItem> results = new LinkedHashMap<>();
        List<String> failed = new ArrayList<>();

        for (Map.Entry<String, Object> entry : mapResponse.entrySet()) {
            String key = entry.getKey();
            try {
                Map<String, String> value = (Map<String, String>) entry.getValue();
                ConditionTemplateItem item = ConditionTemplateItem.builder()
                        .name(value.get("name"))
                        .description(value.get("description"))
                        .spelTemplate(value.get("spelTemplate"))
                        .category(value.get("category"))
                        .classification(value.get("classification"))
                        .build();
                results.put(key, item);
            } catch (Exception e) {
                failed.add(key);
            }
        }

        return new ConditionTemplateGenerationResponse(
                null, null, null,
                Map.of("generatedAt", System.currentTimeMillis()),
                results, failed
        );
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ConditionTemplateItem {
        private String name;
        private String description;
        private String spelTemplate;
        private String category;
        private String classification;
    }
}
