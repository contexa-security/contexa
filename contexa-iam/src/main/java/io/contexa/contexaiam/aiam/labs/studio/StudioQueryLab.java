package io.contexa.contexaiam.aiam.labs.studio;

import io.contexa.contexacore.exception.AIOperationException;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.labs.studio.domain.DataCollectionPlan;
import io.contexa.contexaiam.aiam.labs.studio.domain.IAMDataSet;
import io.contexa.contexaiam.aiam.labs.data.IAMDataCollectionService;
import io.contexa.contexaiam.aiam.labs.studio.service.QueryIntentAnalyzer;
import io.contexa.contexaiam.aiam.labs.studio.service.StudioQueryFormatter;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexacommon.enums.SecurityLevel;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryRequest;
import io.contexa.contexaiam.aiam.protocol.response.StudioQueryResponse;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
public class StudioQueryLab extends AbstractIAMLab<StudioQueryRequest,StudioQueryResponse> {

    private final PipelineOrchestrator orchestrator;
    private final QueryIntentAnalyzer queryIntentAnalyzer;
    private final IAMDataCollectionService dataCollectionService;
    private final StudioQueryFormatter queryFormatter;
    private final StudioQueryVectorService vectorService;

    public StudioQueryLab(PipelineOrchestrator orchestrator,
                          QueryIntentAnalyzer queryIntentAnalyzer,
                          IAMDataCollectionService dataCollectionService,
                          StudioQueryFormatter queryFormatter,
                          StudioQueryVectorService vectorService) {
        super("StudioQuery", "1.0", LabSpecialization.STUDIO_QUERY);
        this.orchestrator = orchestrator;
        this.queryIntentAnalyzer = queryIntentAnalyzer;
        this.dataCollectionService = dataCollectionService;
        this.queryFormatter = queryFormatter;
        this.vectorService = vectorService;
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    @Override
    protected StudioQueryResponse doProcess(StudioQueryRequest request) throws Exception {
        return processRequestAsync(request).block();
    }

    @Override
    protected Mono<StudioQueryResponse> doProcessAsync(StudioQueryRequest request) {
        return processRequestAsync(request);
    }

    @Override
    protected Flux<String> doProcessStream(StudioQueryRequest request) {
        return processStreamingRequest(request);
    }

    public Mono<StudioQueryResponse> processRequestAsync(StudioQueryRequest request) {
        return Mono.fromCallable(() -> {
                    DataCollectionPlan collectionPlan = createDataCollectionPlan(request.getNaturalLanguageQuery());
                    IAMDataSet dataSet = dataCollectionService.studioCollectData(collectionPlan);

                    String formattedData = queryFormatter.formatForAIMData(dataSet);
                    String systemMetadata = queryFormatter.formatSystemMetadata(request);

                    request.withParameter("iamDataContext", formattedData);
                    request.withParameter("systemMetadata", systemMetadata);
                    request.withParameter("requestType", "studio_query");
                    request.withParameter("outputFormat", "json_object");
                    request.withParameter("includeVisualization", true);

                    return request;
                })
                .flatMap(enrichedRequest -> {
                    PipelineConfiguration<StudioQueryContext> config = createStudioQueryPipelineConfig();
                    return orchestrator.execute(enrichedRequest, config, StudioQueryResponse.class);
                })
                .map(response -> (StudioQueryResponse) response)
                .doOnError(error -> {
                    log.error("[DIAGNOSIS] AI Studio diagnosis processing failed: {}", error.getMessage(), error);
                });
    }

    public Flux<String> processStreamingRequest(StudioQueryRequest request) {
        return Flux.defer(() -> {
            try {
                DataCollectionPlan collectionPlan = createDataCollectionPlan(request.getNaturalLanguageQuery());
                IAMDataSet dataSet = dataCollectionService.studioCollectData(collectionPlan);

                String formattedData = queryFormatter.formatForAIMData(dataSet);
                String systemMetadata = queryFormatter.formatSystemMetadata(request);

                request.withParameter("iamDataContext", formattedData);
                request.withParameter("systemMetadata", systemMetadata);
                request.withParameter("requestType", "studio_query_streaming");
                request.withParameter("outputFormat", "natural_language");

                PipelineConfiguration<StudioQueryContext> pipelineConfig = createStudioQueryStreamPipelineConfig();
                return orchestrator.executeStream(request, pipelineConfig)
                        .doOnError(error -> {
                            log.error("[STREAMING] Streaming error: {}", error.getMessage(), error);
                        });

            } catch (Exception e) {
                log.error("Streaming processing error: {}", e.getMessage(), e);
                return Flux.error(new AIOperationException("Streaming processing failed", e));
            }
        });
    }

    private DataCollectionPlan createDataCollectionPlan(String query) {
        try {
            return new DataCollectionPlan(queryIntentAnalyzer, query);
        } catch (Exception e) {
            log.warn("데이터 수집 계획 수립 실패, 폴백 사용: {}", e.getMessage());
            return DataCollectionPlan.createFallback(query);
        }
    }

    private PipelineConfiguration<StudioQueryContext> createStudioQueryPipelineConfig() {
        return (PipelineConfiguration<StudioQueryContext>) PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                .timeoutSeconds(300)
                .build();
    }

    private PipelineConfiguration<StudioQueryContext> createStudioQueryStreamPipelineConfig() {
        return (PipelineConfiguration<StudioQueryContext>) PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .enableStreaming(true)
                .timeoutSeconds(300)
                .build();
    }
}