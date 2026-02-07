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
    private RequestPriority priority = RequestPriority.NORMAL;

    public ResourceNamingSuggestionRequest(ResourceNamingContext context, TemplateType templateType, DiagnosisType diagnosisType) {
        super(context, templateType, diagnosisType);
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
}