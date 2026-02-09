package io.contexa.contexaiam.aiam.labs.resource;

import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNamingSuggestionRequest;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingSuggestionResponse;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
public class ResourceNamingLab extends AbstractIAMLab<ResourceNamingSuggestionRequest, ResourceNamingSuggestionResponse> {

    private final PipelineOrchestrator orchestrator;

    public ResourceNamingLab(PipelineOrchestrator orchestrator) {
        super("ResourceNaming", "1.0", LabSpecialization.RECOMMENDATION_SYSTEM);
        this.orchestrator = orchestrator;
    }

    @Override
    protected ResourceNamingSuggestionResponse doProcess(ResourceNamingSuggestionRequest request) throws Exception {
        return processResourceNamingAsync(request).block();
    }

    @Override
    protected Mono<ResourceNamingSuggestionResponse> doProcessAsync(ResourceNamingSuggestionRequest request) {
        return processResourceNamingAsync(request);
    }

    private Mono<ResourceNamingSuggestionResponse> processResourceNamingAsync(ResourceNamingSuggestionRequest request) {
        PipelineConfiguration config = createPipelineConfig();

        return orchestrator.execute(request, config, ResourceNamingSuggestionResponse.class)
                .onErrorResume(error -> {
                    log.error("Resource naming pipeline failed", error);
                    return Mono.just(createFallbackResponse(
                            request.getResources(), ((Throwable)error).getMessage()));
                });
    }

    private ResourceNamingSuggestionResponse createFallbackResponse(
            List<ResourceNamingSuggestionRequest.ResourceItem> resources, String errorMessage) {

        log.error("Resource naming pipeline completely failed, returning empty result: {}", errorMessage);
        return new ResourceNamingSuggestionResponse(
                List.of(),
                resources.stream()
                        .map(ResourceNamingSuggestionRequest.ResourceItem::getIdentifier)
                        .toList());
    }
}
