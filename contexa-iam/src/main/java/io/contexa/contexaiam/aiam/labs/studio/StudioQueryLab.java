package io.contexa.contexaiam.aiam.labs.studio;

import io.contexa.contexacore.exception.AIOperationException;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.labs.studio.domain.DataCollectionPlan;
import io.contexa.contexaiam.aiam.labs.studio.domain.IAMDataSet;
import io.contexa.contexaiam.aiam.labs.data.IAMDataCollectionService;
import io.contexa.contexaiam.aiam.labs.studio.service.QueryIntentAnalyzer;
import io.contexa.contexaiam.aiam.labs.studio.service.StudioQueryFormatter;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryRequest;
import io.contexa.contexaiam.aiam.protocol.response.StudioQueryResponse;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
public class StudioQueryLab extends AbstractIAMLab<StudioQueryRequest, StudioQueryResponse> {

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
        return processRequestAsyncStream(request);
    }

    public Mono<StudioQueryResponse> processRequestAsync(StudioQueryRequest request) {
        try {
            vectorService.storeQueryRequest(request);
        } catch (Exception e) {
            log.error("Vector store query request failed", e);
        }

        return Mono.fromCallable(() -> enrichRequest(request, false))
                .flatMap(enrichedRequest -> {
                    return orchestrator.execute(enrichedRequest, createPipelineConfig(), StudioQueryResponse.class);
                })
                .map(response -> (StudioQueryResponse) response)
                .doOnSuccess(response -> {
                    try {
                        vectorService.storeQueryResult(request.getRequestId(), response.toString());
                    } catch (Exception e) {
                        log.error("Vector store query result failed", e);
                    }
                })
                .doOnError(error -> {
                    log.error("[DIAGNOSIS] AI Studio diagnosis processing failed: {}", error.getMessage(), error);
                });
    }

    public Flux<String> processRequestAsyncStream(StudioQueryRequest request) {
        try {
            vectorService.storeQueryRequest(request);
        } catch (Exception e) {
            log.error("Vector store query request failed", e);
        }

        return Flux.defer(() -> {
            try {
                StudioQueryRequest enrichedRequest = enrichRequest(request, true);
                return orchestrator.executeStream(enrichedRequest, createStreamPipelineConfig())
                        .doOnError(error -> {
                            log.error("[STREAMING] Streaming error: {}", error.getMessage(), error);
                        });
            } catch (Exception e) {
                log.error("Streaming processing error: {}", e.getMessage(), e);
                return Flux.error(new AIOperationException("Streaming processing failed", e));
            }
        });
    }

    /**
     * Enriches the request with IAM data context and system metadata.
     * Common logic extracted from processRequestAsync and processRequestAsyncStream.
     *
     * @param request the original request
     * @param isStreaming true if streaming mode, false otherwise
     * @return the enriched request
     */
    private StudioQueryRequest enrichRequest(StudioQueryRequest request, boolean isStreaming) {
        DataCollectionPlan collectionPlan = createDataCollectionPlan(request.getNaturalLanguageQuery());
        IAMDataSet dataSet = dataCollectionService.studioCollectData(collectionPlan);

        String formattedData = queryFormatter.formatForAIMData(dataSet);
        String systemMetadata = queryFormatter.formatSystemMetadata(request);

        request.withParameter("iamDataContext", formattedData);
        request.withParameter("systemMetadata", systemMetadata);

        if (isStreaming) {
            request.withParameter("requestType", "studio_query_streaming");
            request.withParameter("outputFormat", "natural_language");
        } else {
            request.withParameter("requestType", "studio_query");
            request.withParameter("outputFormat", "json_object");
            request.withParameter("includeVisualization", true);
        }

        return request;
    }

    private DataCollectionPlan createDataCollectionPlan(String query) {
        try {
            return new DataCollectionPlan(queryIntentAnalyzer, query);
        } catch (Exception e) {
            log.warn("Data collection plan creation failed, using fallback: {}", e.getMessage());
            return DataCollectionPlan.createFallback(query);
        }
    }
}
