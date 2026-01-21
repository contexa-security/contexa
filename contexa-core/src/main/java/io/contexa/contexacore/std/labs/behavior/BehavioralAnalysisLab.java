package io.contexa.contexacore.std.labs.behavior;

import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.BehavioralAnalysisRequest;
import io.contexa.contexacommon.domain.response.BehavioralAnalysisResponse;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarRequest;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.std.components.retriever.BehavioralAnalysisContextRetriever;
import io.contexa.contexacore.std.labs.AbstractAILab;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.opentelemetry.api.trace.Tracer;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

@Slf4j
public class BehavioralAnalysisLab extends AbstractAILab<BehavioralAnalysisRequest, BehavioralAnalysisResponse> {

    private final PipelineOrchestrator orchestrator;
    private final BehaviorVectorService behaviorVectorService;
    private final AINativeProcessor aiNativeProcessor; 

    public BehavioralAnalysisLab(
            Tracer tracer,
            AINativeProcessor aiNativeProcessor, 
            PipelineOrchestrator orchestrator,
            BehavioralAnalysisContextRetriever contextRetriever,
            BehaviorVectorService behaviorVectorService) {
        super("BehavioralAnalysis", tracer);
        this.aiNativeProcessor = aiNativeProcessor; 
        this.orchestrator = orchestrator;
        this.behaviorVectorService = behaviorVectorService;
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    @Override
    protected BehavioralAnalysisResponse doProcess(BehavioralAnalysisRequest request) throws Exception {
        return performBehavioralAnalysis(request).block();
    }

    @Override
    protected Mono<BehavioralAnalysisResponse> doProcessAsync(BehavioralAnalysisRequest request) {
        return performBehavioralAnalysis(request);
    }

    @Override
    protected Flux<String> doProcessStream(BehavioralAnalysisRequest request) {
        return processStreamingRequest(request);
    }

    private Mono<BehavioralAnalysisResponse> performBehavioralAnalysis(AIRequest<BehavioralAnalysisContext> request) {
        
        return Mono.fromCallable(() -> {

                    behaviorVectorService.storeBehavior(request.getContext());

                    PipelineConfiguration<BehavioralAnalysisContext> config = createPipelineConfig();

                    return orchestrator.execute(request, config, BehavioralAnalysisResponse.class)
                            .cast(BehavioralAnalysisResponse.class);
                })
                .flatMap(response -> response)
                .doOnSuccess(response -> {
                    
                    behaviorVectorService.storeAnalysisResult(request.getContext(), (BehavioralAnalysisResponse)response);

                    double riskScore = ((BehavioralAnalysisResponse)response).getBehavioralRiskScore();

                    if (riskScore >= 70.0) {
                        behaviorVectorService.storeThreatPattern(request.getContext(), (BehavioralAnalysisResponse)response);
                        log.warn("[ThreatPattern] 고위험 패턴 벡터 저장소 저장 완료: userId={}, riskScore={}",
                            request.getContext().getUserId(), riskScore);
                    }

                    if (riskScore >= 70.0) { 
                        log.warn("[DIAGNOSIS] 고위험 행동 감지! SOAR 워크플로우 트리거: User={}, RiskScore={}",
                                 request.getContext().getUserId(), riskScore);
                        try {
                            SoarRequest soarRequest = createSoarRequestFromBehavioralAnalysis(request.getContext(), (BehavioralAnalysisResponse)response);
                            aiNativeProcessor.process(soarRequest,  SoarResponse.class)
                                    .subscribe(
                                            soarResponse -> log.info("SOAR 워크플로우 성공적으로 트리거됨: IncidentId={}", ((SoarResponse)soarResponse).getIncidentId()),
                                            soarError -> log.error("SOAR 워크플로우 트리거 실패: {}", ((Throwable)soarError).getMessage(), soarError)
                                    );
                        } catch (Exception e) {
                            log.error("SOAR 요청 생성 또는 트리거 중 오류 발생: {}", e.getMessage(), e);
                        }
                    }
                })
                .doOnError(error -> log.error("[DIAGNOSIS] ===== 행동 분석 실패 =====", error));
    }

    private Flux<String> processStreamingRequest(BehavioralAnalysisRequest request) {
        
        BehavioralAnalysisContext context = request.getContext();

        behaviorVectorService.storeBehavior(context);

        AIRequest<BehavioralAnalysisContext> aiRequest = createAIRequest(context);

        PipelineConfiguration config = createStreamPipelineConfig();

        return orchestrator.executeStream(aiRequest, config)
                .doOnComplete(() -> log.info("[STREAMING] 행동 분석 스트리밍 완료"))
                .doOnError(error -> log.error("[STREAMING] 행동 분석 스트리밍 오류", error));
    }

    public CompletableFuture<Void> performBatchLearning() {
                return behaviorVectorService.runBatchLearning();
    }

    public void learnFromFeedback(String analysisId, boolean isCorrect, String feedback) {
                behaviorVectorService.storeFeedback(analysisId, isCorrect, feedback);
    }

    private AIRequest<BehavioralAnalysisContext> createAIRequest(BehavioralAnalysisContext context) {
        return new AIRequest<>(context, "behavioralAnalysisStreaming", context.getOrganizationId());
    }

    private PipelineConfiguration createPipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                .timeoutSeconds(300)
                .enableCaching(true)
                .build();
    }

    private PipelineConfiguration createStreamPipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .build();
    }

    private String extractActivityType(String activity) {
        if (activity == null) return "UNKNOWN";

        String lower = activity.toLowerCase();
        if (lower.contains("login")) return "LOGIN";
        if (lower.contains("create") || lower.contains("생성")) return "CREATE";
        if (lower.contains("update") || lower.contains("수정")) return "UPDATE";
        if (lower.contains("delete") || lower.contains("삭제")) return "DELETE";
        if (lower.contains("read") || lower.contains("조회")) return "READ";
        if (lower.contains("admin") || lower.contains("관리")) return "ADMIN_ACTION";

        return "OTHER";
    }

    private SoarRequest createSoarRequestFromBehavioralAnalysis(BehavioralAnalysisContext behavioralContext, BehavioralAnalysisResponse behavioralResponse) {
        String incidentId = "BA-" + behavioralResponse.getAnalysisId();
        String threatType = "Behavioral Anomaly: " + behavioralResponse.getRiskLevel().name();
        String description = String.format("사용자 '%s'의 행동에서 고위험 이상 징후가 감지되었습니다. 요약: %s. 상세: %s",
                                           behavioralContext.getUserId(),
                                           behavioralResponse.getSummary(),
                                           behavioralResponse.getAnomalies().stream()
                                                             .map(a -> a.getType() + ": " + a.getDescription())
                                                             .collect(Collectors.joining(", "))
                                          );
        List<String> affectedAssets = List.of(behavioralContext.getUserId(), behavioralContext.getRemoteIp());
        String currentStatus = "Detected by Behavioral Analysis";
        String detectedSource = "IAM Behavioral Analysis System";
        String severity = mapRiskLevelToSoarSeverity(behavioralResponse.getRiskLevel());
        String recommendedActions = "사용자 계정 활동 모니터링 강화, 비정상 세션 종료 고려";
        String organizationId = behavioralContext.getOrganizationId();

        SoarContext soarContext = new SoarContext(
            incidentId, threatType, description, affectedAssets, currentStatus,
            detectedSource, severity, recommendedActions, organizationId
        );

        SoarRequest soarRequest = new SoarRequest(soarContext, "soarAnalysis");
        soarRequest.setIncidentId(incidentId);
        soarRequest.setThreatType(threatType);
        soarRequest.setDescription(description);
        soarRequest.setInitialQuery(description); 

        return soarRequest;
    }

    private String mapRiskLevelToSoarSeverity(BehavioralAnalysisResponse.RiskLevel riskLevel) {
        return switch (riskLevel) {
            case LOW -> "LOW";
            case MEDIUM -> "MEDIUM";
            case HIGH -> "HIGH";
            default -> "MEDIUM";
        };
    }
}
