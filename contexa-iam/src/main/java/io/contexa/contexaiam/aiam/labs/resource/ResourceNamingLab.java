package io.contexa.contexaiam.aiam.labs.resource;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexacommon.enums.SecurityLevel;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNamingSuggestionRequest;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingSuggestionResponse;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class ResourceNamingLab extends AbstractIAMLab<ResourceNamingSuggestionRequest, ResourceNamingSuggestionResponse> {

    private final PipelineOrchestrator orchestrator;
    private final ResourceNamingVectorService vectorService;
    private static final int DEFAULT_BATCH_SIZE = 5;

    public ResourceNamingLab(PipelineOrchestrator orchestrator,
                             ResourceNamingVectorService vectorService) {
        super("ResourceNaming", "1.0", LabSpecialization.RECOMMENDATION_SYSTEM);
        this.orchestrator = orchestrator;
        this.vectorService = vectorService;
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

        try {
            vectorService.storeNamingRequest(request);
        } catch (Exception e) {
            log.error("벡터 저장소 요청 저장 실패", e);
        }

        return executePipelineAsync(request)
                .onErrorResume(error -> {
                    log.error("ResourceNaming 비동기 진단 실패", error);
                    ResourceNamingSuggestionResponse.ProcessingStats errorStats =
                            new ResourceNamingSuggestionResponse.ProcessingStats(
                                    request.getResources().size(), 0, request.getResources().size(), 0);
                    return Mono.just(new ResourceNamingSuggestionResponse(
                            List.of(),
                            request.getResources().stream()
                                    .map(ResourceNamingSuggestionRequest.ResourceItem::getIdentifier)
                                    .toList(),
                            errorStats));
                });
    }

    private Mono<ResourceNamingSuggestionResponse> executePipelineAsync(ResourceNamingSuggestionRequest request) {
        
        long startTime = System.currentTimeMillis();
        List<ResourceNamingSuggestionResponse.ResourceNamingSuggestion> allSuggestions = new ArrayList<>();
        List<String> failedIdentifiers = new ArrayList<>();

        List<List<ResourceNamingSuggestionRequest.ResourceItem>> batches =
                request.getResources().stream()
                        .collect(Collectors.groupingBy(item -> allSuggestions.size() / DEFAULT_BATCH_SIZE))
                        .values()
                        .stream()
                        .toList();

                return processBatchesSequentiallyAsync(batches, 0, allSuggestions, failedIdentifiers, startTime, request.getResources().size());
    }

    private Mono<ResourceNamingSuggestionResponse> processBatchesSequentiallyAsync(
            List<List<ResourceNamingSuggestionRequest.ResourceItem>> batches,
            int currentIndex,
            List<ResourceNamingSuggestionResponse.ResourceNamingSuggestion> allSuggestions,
            List<String> failedIdentifiers,
            long startTime,
            int totalResources) {

        if (currentIndex >= batches.size()) {
            long processingTime = System.currentTimeMillis() - startTime;
            ResourceNamingSuggestionResponse.ProcessingStats stats =
                    ResourceNamingSuggestionResponse.ProcessingStats.builder()
                            .totalRequested(totalResources)
                            .successfullyProcessed(allSuggestions.size())
                            .failed(failedIdentifiers.size())
                            .processingTimeMs(processingTime)
                            .build();

            ResourceNamingSuggestionResponse finalResponse = new ResourceNamingSuggestionResponse(allSuggestions, failedIdentifiers, stats);
            try {
                
                List<ResourceNamingSuggestionRequest.ResourceItem> allResources = batches.stream()
                        .flatMap(List::stream)
                        .collect(Collectors.toList());
                
                ResourceNamingContext context = new ResourceNamingContext();
                ResourceNamingSuggestionRequest originalRequest = new ResourceNamingSuggestionRequest(context, new TemplateType("ResourceNaming"), new DiagnosisType("ResourceNaming"));
                originalRequest.setResources(allResources);
                vectorService.storeNamingResult(originalRequest, finalResponse);
            } catch (Exception e) {
                log.error("벡터 저장소 결과 저장 실패", e);
            }

            return Mono.just(finalResponse);
        }
        List<ResourceNamingSuggestionRequest.ResourceItem> currentBatch = batches.get(currentIndex);
        
        return processBatchAsync(currentBatch)
                .flatMap(batchResponse -> {
                    allSuggestions.addAll(batchResponse.getSuggestions());
                    failedIdentifiers.addAll(batchResponse.getFailedIdentifiers());

                    return processBatchesSequentiallyAsync(batches, currentIndex + 1, allSuggestions, failedIdentifiers, startTime, totalResources);
                })
                .onErrorResume(error -> {
                    log.error("배치 {} 비동기 처리 실패, 다음 배치로 계속 진행", currentIndex + 1, error);

                    currentBatch.forEach(item -> failedIdentifiers.add(item.getIdentifier()));

                    return processBatchesSequentiallyAsync(batches, currentIndex + 1, allSuggestions, failedIdentifiers, startTime, totalResources);
                });
    }

    private Mono<ResourceNamingSuggestionResponse> processBatchAsync(List<ResourceNamingSuggestionRequest.ResourceItem> batch) {
        
        return Mono.fromCallable(() -> createResourceNamingRequest(batch))
                .flatMap(aiRequest -> {
                    PipelineConfiguration config = createResourceNamingPipelineConfig();
                    return orchestrator.execute(aiRequest, config, ResourceNamingSuggestionResponse.class);
                })
                .map(response -> {
                    ResourceNamingSuggestionResponse namingResponse = (ResourceNamingSuggestionResponse) response;
                    return namingResponse != null ? namingResponse : createFallbackResponse(batch, "Pipeline returned null response");
                })
                .onErrorResume(error -> {
                    log.error("비동기 배치 처리 실패", error);
                    String errorMsg = error instanceof Throwable ? ((Throwable) error).getMessage() : error.toString();
                    return Mono.just(createFallbackResponse(batch, errorMsg));
                });
    }

    private PipelineConfiguration createResourceNamingPipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                .timeoutSeconds(60)
                .build();
    }

    private AIRequest<ResourceNamingContext> createResourceNamingRequest(List<ResourceNamingSuggestionRequest.ResourceItem> batch) {
        ResourceNamingContext context = new ResourceNamingContext();

        AIRequest<ResourceNamingContext> request = new AIRequest<>(context, new TemplateType("ResourceNaming"), new DiagnosisType("ResourceNaming"));

        request.withParameter("requestType", "resource_naming");
        request.withParameter("batchSize", batch.size());
        request.withParameter("outputFormat", "json_object");
        request.withParameter("language", "korean");
        request.withParameter("includeDescription", true);

        List<String> identifiers = batch.stream()
                .map(ResourceNamingSuggestionRequest.ResourceItem::getIdentifier)
                .collect(Collectors.toList());
        request.withParameter("identifiers", identifiers);

        List<String> owners = batch.stream()
                .map(ResourceNamingSuggestionRequest.ResourceItem::getOwner)
                .filter(owner -> owner != null && !owner.trim().isEmpty())
                .collect(Collectors.toList());
        request.withParameter("owners", owners);

        return request;
    }

    private ResourceNamingSuggestionResponse createFallbackResponse(List<ResourceNamingSuggestionRequest.ResourceItem> batch, String errorMessage) {
        log.error("[AI 오류] 진짜 6단계 파이프라인 완전 실패, 빈 결과 반환: {}", errorMessage);
        ResourceNamingSuggestionResponse.ProcessingStats fallbackStats =
                new ResourceNamingSuggestionResponse.ProcessingStats(batch.size(), 0, batch.size(), 0);
        return new ResourceNamingSuggestionResponse(
                List.of(),
                batch.stream().map(ResourceNamingSuggestionRequest.ResourceItem::getIdentifier).toList(),
                fallbackStats);
    }
}