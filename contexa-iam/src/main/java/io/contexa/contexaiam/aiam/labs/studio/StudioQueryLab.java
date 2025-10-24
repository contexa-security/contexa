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
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Authorization Studio 자연어 질의 전문 연구소 (PipelineOrchestrator 기반)
 *
 * PipelineOrchestrator.executeStream() → StreamingUniversalPipelineExecutor 자동 선택
 * PipelineOrchestrator.execute() → 일반 진단 전용 executor 선택
 * 스트리밍 + 진단 동시 처리 지원
 */
@Slf4j
@Component
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

    /**
     * AI Studio 비동기 질의 처리 (진단 전용 - JSON 응답)
     */
    public Mono<StudioQueryResponse> processRequestAsync(StudioQueryRequest request) {
        long startTime = System.currentTimeMillis();
        log.info("[DIAGNOSIS] AI Studio 진단 처리 시작: {} (일반 executor 사용)", request.getQuery());

        // 벡터 저장소에 요청 저장
        try {
            vectorService.storeQueryRequest(request);
        } catch (Exception e) {
            log.error("벡터 저장소 요청 저장 실패", e);
        }

        return Mono.fromCallable(() -> {
                    // 1. 질의 의도 분석 및 데이터 수집 계획 수립
                    DataCollectionPlan collectionPlan = createDataCollectionPlan(request.getQuery());
                    log.info("데이터 수집 계획 수립 완료: {}", collectionPlan);

                    // 2. IAM 데이터 수집 (전문 서비스 활용)
                    IAMDataSet dataSet = dataCollectionService.studioCollectData(collectionPlan);
                    log.info("IAM 데이터 수집 완료: {}", dataSet.getSummary());

                    // 3. 🎨 데이터 포맷팅 (전문 서비스 활용)
                    String formattedData = queryFormatter.formatForAIMData(dataSet);
                    String systemMetadata = queryFormatter.formatSystemMetadata(request);

                    log.info("🎨 데이터 포맷팅 완료: {} characters", formattedData.length());

                    // 4. 도메인 전문성: 진단용 AIRequest 구성 (JSON 응답)
                    return createStudioQueryAIRequest(request, formattedData, systemMetadata, false);
                })
                .flatMap(aiRequest -> {
                    log.info("[DIAGNOSIS] PipelineOrchestrator.execute() 호출 - 일반 executor 선택됨");

                    // 5. PipelineOrchestrator.execute() → 일반 진단 전용 executor
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

    /**
     * AI Studio 스트리밍 질의 처리 (진단 + 스트리밍 동시 처리)
     */
    public Flux<String> processStreamingRequest(StudioQueryRequest request) {
        return Flux.defer(() -> {
            try {
                log.info("[STREAMING] AI Studio 스트리밍 시작: {} (StreamingUniversalPipelineExecutor 자동선택)", request.getQuery());

                // 1. 질의 의도 분석 및 데이터 수집 계획 수립 (공통 로직)
                DataCollectionPlan collectionPlan = createDataCollectionPlan(request.getQuery());
                log.info("스트리밍 데이터 수집 계획 수립 완료: {}", collectionPlan);

                // 2. IAM 데이터 수집 (공통 로직)
                IAMDataSet dataSet = dataCollectionService.studioCollectData(collectionPlan);
                log.info("스트리밍 IAM 데이터 수집 완료: {}", dataSet.getSummary());

                // 3. 🎨 데이터 포맷팅 (공통 로직)
                String formattedData = queryFormatter.formatForAIMData(dataSet);
                String systemMetadata = queryFormatter.formatSystemMetadata(request);

                // 4. AI 요청 생성 (스트리밍 + 진단 동시 처리용)
                AIRequest<StudioQueryContext> aiRequest = createStudioQueryAIRequest(request, formattedData, systemMetadata, true);
                log.info("스트리밍+진단 AI 요청 생성 완료");

                // 5. Pipeline 설정 
                PipelineConfiguration pipelineConfig = createStudioQueryStreamPipelineConfig();
                log.info("⚙️ Pipeline 설정 완료");

                log.info("[STREAMING] PipelineOrchestrator.executeStream() 호출 - StreamingUniversalPipelineExecutor 자동선택");
                return orchestrator.executeStream(aiRequest, pipelineConfig)
                        .doOnSubscribe(subscription -> { log.info("📦 [{}][{}] [구독]:", Thread.currentThread().threadId(),Thread.currentThread().getName());})
                        .doOnNext(chunk -> {
                            String chunkStr = chunk != null ? chunk.toString() : "";
//                            log.error("📦 [STREAMING] 청크 수신: {}", Thread.currentThread().threadId());
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

    /**
     * 데이터 수집 계획 수립 (기존 코드 그대로)
     */
    private DataCollectionPlan createDataCollectionPlan(String query) {
        try {
            return new DataCollectionPlan(queryIntentAnalyzer, query);
        } catch (Exception e) {
            log.warn("데이터 수집 계획 수립 실패, 폴백 사용: {}", e.getMessage());
            return DataCollectionPlan.createFallback(query);
        }
    }

    /**
     * Pipeline 설정 구성 (기존 코드 그대로)
     */
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

    /**
     * 도메인 전문성: Studio Query AIRequest 생성 (기존 코드 그대로)

    private AIRequest<StudioQueryContext> createStudioQueryAIRequest(StudioQueryRequest request,
                                                                     String formattedData,
                                                                     String systemMetadata) {
        return createStudioQueryAIRequest(request, formattedData, systemMetadata, false);
    }

    /**
     * 도메인 전문성: Studio Query AIRequest 생성 (기존 코드 그대로)
     */
    private AIRequest<StudioQueryContext> createStudioQueryAIRequest(StudioQueryRequest request,
                                                                     String formattedData,
                                                                     String systemMetadata,
                                                                     boolean isStreaming) {
        StudioQueryContext context = new StudioQueryContext.Builder(SecurityLevel.STANDARD, AuditRequirement.DETAILED)
                .withUserId(request.getUserId())
                .withNaturalLanguageQuery(request.getQuery())
                .build();

        // 스트리밍 여부에 따라 다른 프롬프트 사용
        String promptKey = isStreaming ? "studioQueryStreaming" : "studioQuery";
        AIRequest<StudioQueryContext> aiRequest = new AIRequest<>(context, promptKey, "default-org");

        // Studio Query 전문 메타데이터 설정
        aiRequest.withParameter("naturalLanguageQuery", request.getQuery());
        aiRequest.withParameter("queryType", request.getQueryType());
        aiRequest.withParameter("requestType", isStreaming ? "studio_query_streaming" : "studio_query");
        aiRequest.withParameter("outputFormat", isStreaming ? "natural_language" : "json_object");
        aiRequest.withParameter("userId", request.getUserId());
        aiRequest.withParameter("includeVisualization", !isStreaming);
        aiRequest.withParameter("iamDataContext", formattedData);
        aiRequest.withParameter("systemMetadata", systemMetadata);

        // 디버깅: AI에게 전달하는 파라미터 확인
        log.info("AI 파라미터 - 프롬프트 키: {}", promptKey);
        log.info("AI 파라미터 - naturalLanguageQuery: {}", request.getQuery());
        log.info("AI 파라미터 - iamDataContext 길이: {}", formattedData.length());
        log.info("AI 파라미터 - systemMetadata 길이: {}", systemMetadata.length());
        log.info("AI 파라미터 - isStreaming: {}", isStreaming);

        return aiRequest;
    }

    /**
     * 도메인 전문성: 응답 후처리 및 검증 (기존 코드 그대로)
     */
    private StudioQueryResponse enhanceStudioQueryResponse(StudioQueryResponse response, StudioQueryRequest request) {
        log.debug("Studio Query response post-processing started");

        try {
            // Visualization data validation
            if (response.getVisualizationData() == null) {
                log.debug("No visualization data found, creating default visualization data");
                response.setVisualizationData(createDefaultVisualizationData(request));
            }

            // Security recommendations validation
            if (response.getRecommendations() == null || response.getRecommendations().isEmpty()) {
                log.debug("No security recommendations found, adding default recommendations");
                response.setRecommendations(createDefaultRecommendations(request));
            }

            log.debug("Studio Query response post-processing completed");
            
            // 벡터 저장소에 결과 저장
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
    
    /**
     * 피드백 기반 학습
     * 
     * @param request 원본 요청
     * @param response 생성된 응답
     * @param feedback 사용자 피드백
     */
    public void learnFromFeedback(StudioQueryRequest request, StudioQueryResponse response, String feedback) {
        try {
            String queryId = request.getRequestId();
            boolean isHelpful = response.getConfidenceScore() > 0.7; // 신뢰도 기반 도움 여부 판단
            vectorService.storeFeedback(queryId, isHelpful, feedback);
            log.info("[StudioQueryLab] 피드백 학습 완료: {}", feedback.substring(0, Math.min(50, feedback.length())));
        } catch (Exception e) {
            log.error("[StudioQueryLab] 피드백 학습 실패", e);
        }
    }

    /**
     * 도메인 전문성: Default Visualization Data Creation (기존 코드 그대로)
     */
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

    /**
     * 도메인 전문성: Default Recommendations Creation (기존 코드 그대로)
     */
    private List<StudioQueryResponse.Recommendation> createDefaultRecommendations(StudioQueryRequest request) {
        StudioQueryResponse.Recommendation recommendation = new StudioQueryResponse.Recommendation();

        // 질의 유형에 따른 구체적 권장사항 생성
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

            // 실행 가능한 액션 링크 추가
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

    /**
     * 도메인 전문성: Fallback Response Creation (기존 코드 그대로)
     */
    private StudioQueryResponse createFallbackResponse(StudioQueryRequest request) {
        StudioQueryResponse response = new StudioQueryResponse();
        response.setNaturalLanguageAnswer("죄송합니다. 현재 질의를 처리할 수 없습니다. 잠시 후 다시 시도해주세요.");
        response.setConfidenceScore(0);
        response.setRecommendations(createDefaultRecommendations(request));
        response.setVisualizationData(createDefaultVisualizationData(request));
        return response;
    }

    /**
     * 도메인 전문성: Error Response Creation (기존 코드 그대로)
     */
    private StudioQueryResponse createErrorResponse(StudioQueryRequest request, Exception e) {
        StudioQueryResponse response = new StudioQueryResponse();
        response.setNaturalLanguageAnswer("시스템 오류로 인해 질의를 처리할 수 없습니다: " + e.getMessage());
        response.setConfidenceScore(0);
        response.setRecommendations(createDefaultRecommendations(request));
        response.setVisualizationData(createDefaultVisualizationData(request));
        return response;
    }
}