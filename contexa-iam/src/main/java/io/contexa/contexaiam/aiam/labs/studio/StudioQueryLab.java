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
        long startTime = System.currentTimeMillis();

        try {
            vectorService.storeQueryRequest(request);
        } catch (Exception e) {
            log.error("벡터 저장소 요청 저장 실패", e);
        }

        return Mono.fromCallable(() -> {
                    
                    DataCollectionPlan collectionPlan = createDataCollectionPlan(request.getQuery());

                    IAMDataSet dataSet = dataCollectionService.studioCollectData(collectionPlan);

                    String formattedData = queryFormatter.formatForAIMData(dataSet);
                    String systemMetadata = queryFormatter.formatSystemMetadata(request);

                    return createStudioQueryAIRequest(request, formattedData, systemMetadata, false);
                })
                .flatMap(aiRequest -> {

                    PipelineConfiguration config = createStudioQueryPipelineConfig();
                    return orchestrator.execute(aiRequest, config, StudioQueryResponse.class);
                })
                .map(response -> {
                    long endTime = System.currentTimeMillis();
                                        return (StudioQueryResponse) response;
                })
                .doOnError(error -> {
                    if (error instanceof Throwable throwable) {
                        log.error("[DIAGNOSIS] AI Studio 진단 처리 실패: {}", throwable.getMessage(), throwable);
                    }
                });
    }

    public Flux<String> processStreamingRequest(StudioQueryRequest request) {
        return Flux.defer(() -> {
            try {

                DataCollectionPlan collectionPlan = createDataCollectionPlan(request.getQuery());

                IAMDataSet dataSet = dataCollectionService.studioCollectData(collectionPlan);

                String formattedData = queryFormatter.formatForAIMData(dataSet);
                String systemMetadata = queryFormatter.formatSystemMetadata(request);

                AIRequest<StudioQueryContext> aiRequest = createStudioQueryAIRequest(request, formattedData, systemMetadata, true);

                PipelineConfiguration pipelineConfig = createStudioQueryStreamPipelineConfig();
                
                                return orchestrator.executeStream(aiRequest, pipelineConfig)
                        .doOnSubscribe(subscription -> { })
                        .doOnNext(chunk -> {
                            String chunkStr = chunk != null ? chunk.toString() : "";

                        })
                        .doOnComplete(() -> {
                                                    })
                        .doOnError(error -> {
                            if (error instanceof Throwable) {
                                log.error("[STREAMING] 스트리밍 오류: {}", ((Throwable) error).getMessage(), error);
                            } else {
                                log.error("[STREAMING] 스트리밍 오류: {}", error.toString(), error);
                            }
                        });

            } catch (Exception e) {
                log.error("스트리밍 처리 중 오류 발생: {}", e.getMessage(), e);
                return Flux.error(new AIOperationException("스트리밍 처리 실패", e));
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

    private PipelineConfiguration createStudioQueryPipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                .timeoutSeconds(300)
                .build();
    }

    private PipelineConfiguration createStudioQueryStreamPipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .timeoutSeconds(300)
                .build();
    }

    private AIRequest<StudioQueryContext> createStudioQueryAIRequest(StudioQueryRequest request,
                                                                     String formattedData,
                                                                     String systemMetadata,
                                                                     boolean isStreaming) {
        StudioQueryContext context = new StudioQueryContext.Builder(SecurityLevel.STANDARD, AuditRequirement.DETAILED)
                .withUserId(request.getUserId())
                .withNaturalLanguageQuery(request.getQuery())
                .build();

        String promptKey = isStreaming ? "studioQueryStreaming" : "studioQuery";
        AIRequest<StudioQueryContext> aiRequest = new AIRequest<>(context, promptKey, "default-org");

        aiRequest.withParameter("naturalLanguageQuery", request.getQuery());
        aiRequest.withParameter("queryType", request.getQueryType());
        aiRequest.withParameter("requestType", isStreaming ? "studio_query_streaming" : "studio_query");
        aiRequest.withParameter("outputFormat", isStreaming ? "natural_language" : "json_object");
        aiRequest.withParameter("userId", request.getUserId());
        aiRequest.withParameter("includeVisualization", !isStreaming);
        aiRequest.withParameter("iamDataContext", formattedData);
        aiRequest.withParameter("systemMetadata", systemMetadata);

        return aiRequest;
    }

    private StudioQueryResponse enhanceStudioQueryResponse(StudioQueryResponse response, StudioQueryRequest request) {
        
        try {
            
            if (response.getVisualizationData() == null) {
                                response.setVisualizationData(createDefaultVisualizationData(request));
            }

            if (response.getRecommendations() == null || response.getRecommendations().isEmpty()) {
                                response.setRecommendations(createDefaultRecommendations(request));
            }

            try {
                vectorService.storeQueryResult(request, response);
            } catch (Exception ve) {
                log.error("벡터 저장소 결과 저장 실패", ve);
            }
            
            return response;

        } catch (Exception e) {
            log.error("Response post-processing failed", e);
            return response;
        }
    }

    public void learnFromFeedback(StudioQueryRequest request, StudioQueryResponse response, String feedback) {
        try {
            String queryId = request.getRequestId();
            boolean isHelpful = response.getConfidenceScore() > 0.7; 
            vectorService.storeFeedback(queryId, isHelpful, feedback);
                    } catch (Exception e) {
            log.error("[StudioQueryLab] 피드백 학습 실패", e);
        }
    }

    private StudioQueryResponse.VisualizationData createDefaultVisualizationData(StudioQueryRequest request) {
        StudioQueryResponse.VisualizationData vizData = new StudioQueryResponse.VisualizationData();

        StudioQueryResponse.VisualizationData.Node queryNode = new StudioQueryResponse.VisualizationData.Node();
        queryNode.setId("query-1");
        queryNode.setLabel("사용자 질의");
        queryNode.setType("QUERY");
        queryNode.getMetadata().put("query", request.getQuery());

        StudioQueryResponse.VisualizationData.Node resultNode = new StudioQueryResponse.VisualizationData.Node();
        resultNode.setId("result-1");
        resultNode.setLabel("분석 결과");
        resultNode.setType("RESULT");

        vizData.getNodes().add(queryNode);
        vizData.getNodes().add(resultNode);

        StudioQueryResponse.VisualizationData.Edge edge = new StudioQueryResponse.VisualizationData.Edge();
        edge.setId("query-to-result");
        edge.setSource("query-1");
        edge.setTarget("result-1");
        edge.setLabel("분석");
        edge.setType("ANALYSIS");

        vizData.getEdges().add(edge);

        return vizData;
    }

    private List<StudioQueryResponse.Recommendation> createDefaultRecommendations(StudioQueryRequest request) {
        StudioQueryResponse.Recommendation recommendation = new StudioQueryResponse.Recommendation();

        String query = request.getQuery().toLowerCase();

        if (query.contains("누가") || query.contains("접근") || query.contains("권한")) {
            recommendation.setTitle("권한 현황 상세 검토");
            recommendation.setDescription("질의하신 권한 관련 사항을 더 자세히 검토해보시기 바랍니다.");
            recommendation.setPriority(2);
            recommendation.setActionItems(List.of(
                    "사용자별 권한 현황 확인",
                    "그룹별 역할 검토",
                    "불필요한 권한 식별 및 제거"
            ));

            StudioQueryResponse.ActionLink usersLink = new StudioQueryResponse.ActionLink();
            usersLink.setText("사용자 관리");
            usersLink.setUrl("/admin/users");
            usersLink.setType("PRIMARY");

            StudioQueryResponse.ActionLink groupsLink = new StudioQueryResponse.ActionLink();
            groupsLink.setText("그룹 관리");
            groupsLink.setUrl("/admin/groups");
            groupsLink.setType("SECONDARY");

            recommendation.setActionLinks(List.of(usersLink, groupsLink));

        } else {
            recommendation.setTitle("시스템 보안 점검");
            recommendation.setDescription("전반적인 시스템 보안 상태를 점검하고 개선하세요.");
            recommendation.setPriority(3);
            recommendation.setActionItems(List.of(
                    "전체 권한 체계 검토",
                    "정책 및 규칙 업데이트",
                    "접근 로그 분석"
            ));

            StudioQueryResponse.ActionLink policiesLink = new StudioQueryResponse.ActionLink();
            policiesLink.setText("정책 관리");
            policiesLink.setUrl("/admin/policies");
            policiesLink.setType("SECONDARY");

            recommendation.setActionLinks(List.of(policiesLink));
        }

        recommendation.setType("ANALYSIS_BASED");
        return List.of(recommendation);
    }

    private StudioQueryResponse createFallbackResponse(StudioQueryRequest request) {
        StudioQueryResponse response = new StudioQueryResponse();
        response.setNaturalLanguageAnswer("죄송합니다. 현재 질의를 처리할 수 없습니다. 잠시 후 다시 시도해주세요.");
        response.setConfidenceScore(0);
        response.setRecommendations(createDefaultRecommendations(request));
        response.setVisualizationData(createDefaultVisualizationData(request));
        return response;
    }

    private StudioQueryResponse createErrorResponse(StudioQueryRequest request, Exception e) {
        StudioQueryResponse response = new StudioQueryResponse();
        response.setNaturalLanguageAnswer("시스템 오류로 인해 질의를 처리할 수 없습니다: " + e.getMessage());
        response.setConfidenceScore(0);
        response.setRecommendations(createDefaultRecommendations(request));
        response.setVisualizationData(createDefaultVisualizationData(request));
        return response;
    }
}