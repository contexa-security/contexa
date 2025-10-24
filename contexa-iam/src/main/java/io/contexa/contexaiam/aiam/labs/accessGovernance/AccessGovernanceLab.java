package io.contexa.contexaiam.aiam.labs.accessGovernance;

import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.components.retriever.AccessGovernanceContextRetriever;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.protocol.context.AccessGovernanceContext;
import io.contexa.contexaiam.aiam.protocol.request.AccessGovernanceRequest;
import io.contexa.contexaiam.aiam.protocol.response.AccessGovernanceResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * 권한 거버넌스 분석 Lab
 *
 * 시스템 전체 권한 분포와 사용 현황을 분석하여 잠재적 이상 징후를 탐지하는 AI Lab
 * 예방적 보안을 구현하여 위협이 발생하기 전에 시스템이 가진 잠재적 위험 요소를 AI가 미리 찾아내어 보고
 * 
 * Lab 목표:
 * - 권한 배분 최적화: "우리 시스템의 권한 배분 상태가 전반적으로 건강하고 최적화되어 있는가?"
 * - 과도한 권한 탐지: "과도한 권한을 가진 사용자를 찾아줘"
 * - 미사용 권한 식별: "사용하지 않는 권한이 있나?"
 * - 권한 상속 경로 추적: "권한 상속 구조가 올바른가?"
 * - 업무 분리 위반 검사: "업무 분리 원칙에 위반되는 권한 배분이 있는가?"
 */
@Slf4j
@Component
public class AccessGovernanceLab extends AbstractIAMLab<AccessGovernanceRequest, AccessGovernanceResponse> {

    private final PipelineOrchestrator orchestrator;
    private final AccessVectorService accessVectorService;

    public AccessGovernanceLab(
            io.opentelemetry.api.trace.Tracer tracer,
            PipelineOrchestrator orchestrator,
            AccessGovernanceContextRetriever contextRetriever,
            AccessVectorService accessVectorService) {
        super(tracer, "AccessGovernance", "1.0", LabSpecialization.SECURITY_ANALYSIS);
        this.orchestrator = orchestrator;
        this.accessVectorService = accessVectorService;
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    @Override
    protected AccessGovernanceResponse doProcess(AccessGovernanceRequest request) throws Exception {
        return performAccessGovernanceAnalysis(request).block();
    }

    @Override
    protected Mono<AccessGovernanceResponse> doProcessAsync(AccessGovernanceRequest request) {
        return performAccessGovernanceAnalysis(request);
    }

    @Override
    protected Flux<String> doProcessStream(AccessGovernanceRequest request) {
        return processStreamingRequest(request);
    }

    /**
     * 핵심: 권한 거버넌스 분석 + Vector DB 저장
     */
    private Mono<AccessGovernanceResponse> performAccessGovernanceAnalysis(AIRequest<AccessGovernanceContext> request) {
        log.info("[DIAGNOSIS] ===== 권한 거버넌스 분석 시작 ===== Scope: {}, Type: {}", 
                request.getContext().getAuditScope(), 
                request.getContext().getAnalysisType());

        return Mono.fromCallable(() -> {
                accessVectorService.storeAnalysisRequest(request.getContext());
                PipelineConfiguration config = createPipelineConfig();
                return orchestrator.execute(request, config, AccessGovernanceResponse.class)
                            .cast(AccessGovernanceResponse.class);
                })
                .flatMap(response -> response)
                .doOnSuccess(response -> {
                    AccessGovernanceResponse accessGovernanceResponse = (AccessGovernanceResponse)response;
                    accessVectorService.storeAnalysisResult(request.getContext(), accessGovernanceResponse);
                    log.info("[DIAGNOSIS] ===== 권한 거버넌스 분석 완료 ===== 점수: {}, 위험도: {}", 
                            accessGovernanceResponse.getOverallGovernanceScore(), accessGovernanceResponse.getRiskLevel());
                })
                .doOnError(error -> log.error("[DIAGNOSIS] ===== 권한 거버넌스 분석 실패 =====", error));
    }

    /**
     * 스트리밍 처리 (실시간 분석 과정 전달)
     */
    private Flux<String> processStreamingRequest(AccessGovernanceRequest request) {
        log.info("[STREAMING] 권한 거버넌스 분석 스트리밍 시작 - Scope: {}, Type: {}", 
                request.getContext().getAuditScope(), 
                request.getContext().getAnalysisType());

        AccessGovernanceContext context = request.getContext();
        accessVectorService.storeAnalysisRequest(context);
        PipelineConfiguration config = createStreamPipelineConfig();

        return orchestrator.executeStream(request, config)
                .doOnComplete(() -> log.info("[STREAMING] 권한 거버넌스 분석 스트리밍 완료"))
                .doOnError(error -> log.error("[STREAMING] 권한 거버넌스 분석 스트리밍 오류", error));
    }

    // 벡터 저장 관련 메서드들은 AccessVectorService로 이관됨

    /**
     * 관리자 피드백 학습
     */
    public void learnFromFeedback(String reportId, boolean isCorrect, String feedback) {
        log.info("피드백 학습: reportId={}, correct={}", reportId, isCorrect);
        accessVectorService.storeFeedback(reportId, isCorrect, feedback);
    }

    private AIRequest<AccessGovernanceContext> createAIRequest(AccessGovernanceContext context) {
        return new AIRequest<>(context, "accessGovernanceAnalysis", context.getOrganizationId());
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
} 