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

    public StudioQueryLab(io.opentelemetry.api.trace.Tracer tracer,
                          PipelineOrchestrator orchestrator,
                          QueryIntentAnalyzer queryIntentAnalyzer,
                          IAMDataCollectionService dataCollectionService,
                          StudioQueryFormatter queryFormatter,
                          StudioQueryVectorService vectorService) {
        super(tracer, "StudioQuery", "1.0", LabSpecialization.STUDIO_QUERY);

        this.orchestrator = orchestrator;
        this.queryIntentAnalyzer = queryIntentAnalyzer;
        this.dataCollectionService = dataCollectionService;
        this.queryFormatter = queryFormatter;
        this.vectorService = vectorService;

        log.info("StudioQueryLab initialized - PipelineOrchestrator 기반 with Vector Storage");
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
        log.info("[DIAGNOSIS] AI Studio 진단 처리 시작: {} (일반 executor 사용)", request.getQuery());

        
        try {
            vectorService.storeQueryRequest(request);
        } catch (Exception e) {
            log.error("벡터 저장소 요청 저장 실패", e);
        }

        return Mono.fromCallable(() -> {
                    
                    DataCollectionPlan collectionPlan = createDataCollectionPlan(request.getQuery());
                    log.info("데이터 수집 계획 수립 완료: {}", collectionPlan);

                    
                    IAMDataSet dataSet = dataCollectionService.studioCollectData(collectionPlan);
                    log.info("IAM 데이터 수집 완료: {}", dataSet.getSummary());

                    
                    String formattedData = queryFormatter.formatForAIMData(dataSet);
                    String systemMetadata = queryFormatter.formatSystemMetadata(request);

                    log.info("🎨 데이터 포맷팅 완료: {} characters", formattedData.length());

                    
                    return createStudioQueryAIRequest(request, formattedData, systemMetadata, false);
                })
                .flatMap(aiRequest -> {
                    log.info("[DIAGNOSIS] PipelineOrchestrator.execute() 호출 - 일반 executor 선택됨");

                    
                    PipelineConfiguration config = createStudioQueryPipelineConfig();
                    return orchestrator.execute(aiRequest, config, StudioQueryResponse.class);
                })
                .map(response -> {
                    long endTime = System.currentTimeMillis();
                    log.info("[DIAGNOSIS] AI Studio 진단 처리 완료 ({}ms): JSON 응답 생성", endTime - startTime);
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
                log.info("[STREAMING] AI Studio 스트리밍 시작: {} (StreamingUniversalPipelineExecutor 자동선택)", request.getQuery());

                
                DataCollectionPlan collectionPlan = createDataCollectionPlan(request.getQuery());
                log.info("스트리밍 데이터 수집 계획 수립 완료: {}", collectionPlan);

                
                IAMDataSet dataSet = dataCollectionService.studioCollectData(collectionPlan);
                log.info("스트리밍 IAM 데이터 수집 완료: {}", dataSet.getSummary());

                
                String formattedData = queryFormatter.formatForAIMData(dataSet);
                String systemMetadata = queryFormatter.formatSystemMetadata(request);

                
                AIRequest<StudioQueryContext> aiRequest = createStudioQueryAIRequest(request, formattedData, systemMetadata, true);
                log.info("스트리밍+진단 AI 요청 생성 완료");

                
                PipelineConfiguration pipelineConfig = createStudioQueryStreamPipelineConfig();
                log.info("⚙️ Pipeline 설정 완료");

                log.info("[STREAMING] PipelineOrchestrator.executeStream() 호출 - StreamingUniversalPipelineExecutor 자동선택");
                return orchestrator.executeStream(aiRequest, pipelineConfig)
                        .doOnSubscribe(subscription -> { log.info("[{}][{}] [구독]:", Thread.currentThread().threadId(),Thread.currentThread().getName());})
                        .doOnNext(chunk -> {
                            String chunkStr = chunk != null ? chunk.toString() : "";

                        })
                        .doOnComplete(() -> {
                            log.info("[STREAMING] StudioQuery 스트리밍 완료 (진단 결과도 함께 수집됨)");
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

        
        log.info("AI 파라미터 - 프롬프트 키: {}", promptKey);
        log.info("AI 파라미터 - naturalLanguageQuery: {}", request.getQuery());
        log.info("AI 파라미터 - iamDataContext 길이: {}", formattedData.length());
        log.info("AI 파라미터 - systemMetadata 길이: {}", systemMetadata.length());
        log.info("AI 파라미터 - isStreaming: {}", isStreaming);

        return aiRequest;
    }

    
    private StudioQueryResponse enhanceStudioQueryResponse(StudioQueryResponse response, StudioQueryRequest request) {
        log.debug("Studio Query response post-processing started");

        try {
            
            if (response.getVisualizationData() == null) {
                log.debug("No visualization data found, creating default visualization data");
                response.setVisualizationData(createDefaultVisualizationData(request));
            }

            
            if (response.getRecommendations() == null || response.getRecommendations().isEmpty()) {
                log.debug("No security recommendations found, adding default recommendations");
                response.setRecommendations(createDefaultRecommendations(request));
            }

            log.debug("Studio Query response post-processing completed");
            
            
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
            log.info("[StudioQueryLab] 피드백 학습 완료: {}", feedback.substring(0, Math.min(50, feedback.length())));
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