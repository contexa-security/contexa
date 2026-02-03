package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.enums.RequestPriority;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.*;

import java.util.List;
import java.util.Map;

@Getter
@Setter
public class ResourceNamingSuggestionRequest extends AIRequest<ResourceNamingContext> {

    private List<ResourceItem> resources;
    private int batchSize = 5;
    private RequestPriority priority = RequestPriority.NORMAL;

    public ResourceNamingSuggestionRequest(DomainContext context, TemplateType templateType, DiagnosisType diagnosisType) {
        super(null, templateType, diagnosisType);
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ResourceItem {

        private String identifier;

        private String owner;

        private Map<String, String> metadata;

        public static ResourceItem fromMap(Map<String, String> resourceMap) {
            return ResourceItem.builder()
                    .identifier(resourceMap.get("identifier"))
                    .owner(resourceMap.get("owner"))
                    .build();
        }
    }

    public static ResourceNamingSuggestionRequest fromMapList(List<Map<String, String>> resourceMaps) {
        List<ResourceItem> items = resourceMaps.stream()
                .map(ResourceItem::fromMap)
                .toList();
        ResourceNamingContext context = new ResourceNamingContext();
        ResourceNamingSuggestionRequest resourceNamingSuggestionRequest = new ResourceNamingSuggestionRequest(context, new TemplateType("ResourceNaming"), new DiagnosisType("ResourceNaming"));
        resourceNamingSuggestionRequest.setResources(items);
        return resourceNamingSuggestionRequest;
    }
} 