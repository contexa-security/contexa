package io.contexa.contexaiam.aiam.strategy;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import io.contexa.contexaiam.aiam.labs.resource.ResourceNamingLab;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNamingSuggestionRequest;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingSuggestionResponse;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Slf4j
public class ResourceNamingDiagnosisStrategy extends AbstractAIStrategy<ResourceNamingContext, ResourceNamingSuggestionResponse> {

    public ResourceNamingDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
    }

    @Override
    public DiagnosisType getSupportedType() {
        return new DiagnosisType("ResourceNaming");
    }

    @Override
    public int getPriority() {
        return 10;
    }

    @Override
    protected void validateRequest(AIRequest<ResourceNamingContext> request) throws DiagnosisException {
        List<Map<String, String>> resources = (List<Map<String, String>>) request.getParameter("resources", List.class);

        if (resources == null || resources.isEmpty()) {
            throw new DiagnosisException("RESOURCE_NAMING", "MISSING_RESOURCES",
                    "resources 파라미터가 필요합니다");
        }
    }

    @Override
    protected Class<?> getLabType() {
        return ResourceNamingLab.class;
    }

    @Override
    protected Object convertLabRequest(AIRequest<ResourceNamingContext> request) throws DiagnosisException {
        try {
            List<Map<String, String>> legacyResources = (List<Map<String, String>>) request.getParameter("resources", List.class);
            return ResourceNamingSuggestionRequest.fromMapList(legacyResources);

        } catch (ClassCastException e) {
            throw new DiagnosisException("RESOURCE_NAMING", "INVALID_RESOURCES_FORMAT",
                    "resources 파라미터 형식이 올바르지 않습니다", e);
        }
    }

    @Override
    protected ResourceNamingSuggestionResponse processLabExecution(Object lab, Object labRequest, AIRequest<ResourceNamingContext> request) throws Exception {
        AILab<ResourceNamingSuggestionRequest, ResourceNamingSuggestionResponse> resourceNamingLab = (ResourceNamingLab) lab;
        ResourceNamingSuggestionRequest namingRequest = (ResourceNamingSuggestionRequest) labRequest;

        return resourceNamingLab.process(namingRequest);
    }

    @Override
    protected Mono<ResourceNamingSuggestionResponse> processLabExecutionAsync(Object lab, Object labRequest, AIRequest<ResourceNamingContext> originRequest) {
        AILab<ResourceNamingSuggestionRequest, ResourceNamingSuggestionResponse> resourceNamingLab = (ResourceNamingLab) lab;
        ResourceNamingSuggestionRequest namingRequest = (ResourceNamingSuggestionRequest) labRequest;

        return resourceNamingLab.processAsync(namingRequest);
    }

}