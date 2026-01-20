package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexacommon.domain.request.IAMRequest;
import lombok.*;

import java.util.List;
import java.util.Map;



@Getter
@Setter
public class ResourceNamingSuggestionRequest extends IAMRequest<ResourceNamingContext> {

    private List<ResourceItem> resources;
    private int batchSize = 5;
    private RequestPriority priority = RequestPriority.NORMAL;

    public ResourceNamingSuggestionRequest() {
        this(null, null);
    }

    public ResourceNamingSuggestionRequest(ResourceNamingContext context, String operation) {
        super(context, operation);
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
        ResourceNamingSuggestionRequest resourceNamingSuggestionRequest = new ResourceNamingSuggestionRequest();
        resourceNamingSuggestionRequest.setResources(items);
        return resourceNamingSuggestionRequest;
    }
} 