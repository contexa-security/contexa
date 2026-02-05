package io.contexa.contexacore.std.labs.risk;

import io.contexa.contexacore.std.labs.AbstractAILab;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacommon.domain.TrustAssessment;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.RiskAssessmentRequest;
import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import io.contexa.contexacommon.enums.RequestPriority;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class RiskAssessmentLab extends AbstractAILab<RiskAssessmentRequest, RiskAssessmentResponse> {

    private final PipelineOrchestrator orchestrator;
    private final RiskContextEnricher contextEnricher;
    private final RiskAssessmentVectorService vectorService;

    private static final int MAX_ENRICHMENT_TIME_MS = 3000;
    private static final double MIN_CONFIDENCE_THRESHOLD = 0.7;

    @Autowired
    public RiskAssessmentLab(AINativeProcessor ainativeProcessor,
                             PipelineOrchestrator orchestrator,
                             RiskContextEnricher contextEnricher,
                             RiskAssessmentVectorService vectorService) {
        super("RiskAssessment");

        this.orchestrator = orchestrator;
        this.contextEnricher = contextEnricher;
        this.vectorService = vectorService;
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    @Override
    protected RiskAssessmentResponse doProcess(RiskAssessmentRequest request) throws Exception {
        return performRiskAssessment(request).block();
    }

    @Override
    protected Mono<RiskAssessmentResponse> doProcessAsync(RiskAssessmentRequest request) {
        return performRiskAssessment(request);
    }

    @Override
    protected Flux<String> doProcessStream(RiskAssessmentRequest request) {
        return processStreamingRequest(request);
    }

    private Mono<RiskAssessmentResponse> performRiskAssessment(RiskAssessmentRequest request) {
        long totalStartTime = System.currentTimeMillis();
        String assessmentId = generateAssessmentId();

        try {
            vectorService.storeRiskAssessmentRequest(request);
        } catch (Exception e) {
            log.error("벡터 저장소 요청 저장 실패", e);
        }

        return Mono.just(request.getContext())
                .flatMap(ctx -> {
                    
                    long enrichStart = System.currentTimeMillis();
                    
                    return enrichContextWithTimeout(ctx, assessmentId)
                            .doOnSuccess(enrichedContext -> {
                                long enrichTime = System.currentTimeMillis() - enrichStart;
                                                            });
                })
                .flatMap(enrichedContext -> {
                    
                    long requestStart = System.currentTimeMillis();
                    
                    PipelineConfiguration config = createRiskAssessmentPipelineConfig();

                    long requestTime = System.currentTimeMillis() - requestStart;

                    long pipelineStart = System.currentTimeMillis();
                    
                    return orchestrator.execute(request, config, RiskAssessmentResponse.class)
                            .doOnSuccess(response -> {
                                long pipelineTime = System.currentTimeMillis() - pipelineStart;
                                                            });
                })
                .map(response -> {
                    
                    long totalTime = System.currentTimeMillis() - totalStartTime;

                    try {
                        vectorService.storeRiskAssessmentResult(request, (RiskAssessmentResponse) response);
                    } catch (Exception e) {
                        log.error("벡터 저장소 결과 저장 실패", e);
                    }

                    return (RiskAssessmentResponse) response;
                })
                .doOnError(error -> {
                    long totalTime = System.currentTimeMillis() - totalStartTime;
                    log.error("[{}] ===== 위험 평가 진단 실패 ===== 총 처리시간: {}ms, 오류: {}",
                            assessmentId, totalTime,
                            error instanceof Throwable ? ((Throwable) error).getMessage() : error.toString());
                });
    }

    private Flux<String> processStreamingRequest(RiskAssessmentRequest request) {
        return Flux.defer(() -> {
            try {
                String assessmentId = generateAssessmentId();
                RiskAssessmentContext context = request.getContext();
                RiskAssessmentContext enrichedContext = contextEnricher.enrichContext(context);
                request.setContext(enrichedContext);
                PipelineConfiguration pipelineConfig = createRiskAssessmentStreamPipelineConfig();

                return orchestrator.executeStream(request, pipelineConfig)
                        .map(chunk -> {

                            return chunk != null ? chunk.toString() : "";
                        })
                        .doOnSubscribe(subscription -> { })
                        .doOnComplete(() -> {
                                                    })
                        .doOnError(error -> {
                            log.error("[{}] [STREAMING] 스트리밍 오류: {}", assessmentId,
                                    error instanceof Throwable ? ((Throwable) error).getMessage() : error.toString());
                        })
                        .onErrorResume(error -> {
                            
                            return Flux.just(
                                    "위험 평가 중 오류가 발생했습니다.",
                                    "안전을 위해 보수적인 평가를 적용합니다.",
                                    "권장 조치: 접근 제한"
                            );
                        });

            } catch (Exception e) {
                log.error("스트리밍 처리 중 오류 발생: {}", e.getMessage(), e);
                return Flux.error(new RuntimeException("RiskAssessment 스트리밍 처리 실패", e));
            }
        });
    }

    private PipelineConfiguration createRiskAssessmentPipelineConfig() {
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

    private PipelineConfiguration createRiskAssessmentStreamPipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .timeoutSeconds(300)
                .enableCaching(true)
                .enableStreaming(true)
                .build();
    }

    private Mono<RiskAssessmentContext> enrichContextWithTimeout(RiskAssessmentContext context, String assessmentId) {
        
        final AtomicLong enrichmentStart = new AtomicLong(System.currentTimeMillis());

        return Mono.defer(() -> {
            enrichmentStart.set(System.currentTimeMillis()); 
            
            return Mono.fromCallable(() -> contextEnricher.enrichContext(context))
                    
                    .subscribeOn(Schedulers.boundedElastic())
                    .timeout(java.time.Duration.ofMillis(MAX_ENRICHMENT_TIME_MS))
                    .doOnSuccess(enrichedContext -> {
                        long enrichmentTime = System.currentTimeMillis() - enrichmentStart.get();

                        if (enrichmentTime > MAX_ENRICHMENT_TIME_MS) {
                            log.warn("[{}] 컨텍스트 강화 시간 초과: {}ms > {}ms",
                                    assessmentId, enrichmentTime, MAX_ENRICHMENT_TIME_MS);
                        }

                        try {
                            validateEnrichedContext(enrichedContext, assessmentId);
                        } catch (Exception e) {
                            log.error("[{}] 컨텍스트 검증 실패: {}", assessmentId, e.getMessage());
                        }

                                            })
                    .doOnError(TimeoutException.class, error -> {
                        log.warn("[{}] 컨텍스트 강화 타임아웃: {}ms 초과",
                                assessmentId, MAX_ENRICHMENT_TIME_MS);
                    })
                    .doOnError(error -> !(error instanceof TimeoutException), error -> {
                        log.warn("[{}] 컨텍스트 강화 실패: {}", assessmentId, error.getMessage());
                    })
                    .onErrorResume(error -> {
                        log.error("[{}] 컨텍스트 강화 실패: {}", assessmentId, error.getMessage(), error);

                        context.withEnvironmentAttribute("enrichmentError", error.getMessage());
                        context.withEnvironmentAttribute("enrichmentFallback", true);
                        return Mono.just(context);
                    });
        });
    }

    private void validateEnrichedContext(RiskAssessmentContext context, String assessmentId) {
        int validationScore = 0;
        int maxScore = 100;

        if (context.getUserId() != null && !context.getUserId().trim().isEmpty()) validationScore += 20;
        if (context.getResourceIdentifier() != null && !context.getResourceIdentifier().trim().isEmpty()) validationScore += 20;
        if (context.getActionType() != null && !context.getActionType().trim().isEmpty()) validationScore += 10;
        if (!context.getBehaviorMetrics().isEmpty()) validationScore += 20;
        if (!context.getEnvironmentAttributes().isEmpty()) validationScore += 15;
        if (context.getHistoryContext() != null && !context.getHistoryContext().trim().isEmpty()) validationScore += 15;

        double qualityScore = (double) validationScore / maxScore;
        context.withEnvironmentAttribute("contextQualityScore", qualityScore);

        if (qualityScore < 0.5) {
            log.warn("[{}] 컨텍스트 품질이 낮음: {}% < 50%", assessmentId, Math.round(qualityScore * 100));
        }
    }

    private String generateAssessmentId() {
        return "RISK-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 1000);
    }

}
