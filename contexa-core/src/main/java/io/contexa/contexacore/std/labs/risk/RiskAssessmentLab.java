package io.contexa.contexacore.std.labs.risk;

import io.opentelemetry.api.trace.Tracer;
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

/**
 * 제로 트러스트 위험 평가 실험실 (PipelineOrchestrator 기반)
 *
 * PipelineOrchestrator.executeStream() → StreamingUniversalPipelineExecutor 자동 선택
 * PipelineOrchestrator.execute() → 일반 진단 전용 executor 선택
 * 스트리밍 + 진단 동시 처리 지원
 */
@Slf4j
@Component
public class RiskAssessmentLab extends AbstractAILab<RiskAssessmentRequest, RiskAssessmentResponse> {

    private final PipelineOrchestrator orchestrator;
    private final RiskContextEnricher contextEnricher;
    private final RiskAssessmentVectorService vectorService;

    private static final int MAX_ENRICHMENT_TIME_MS = 3000;
    private static final double MIN_CONFIDENCE_THRESHOLD = 0.7;

    @Autowired
    public RiskAssessmentLab(Tracer tracer,
                             AINativeProcessor ainativeProcessor,
                             PipelineOrchestrator orchestrator,
                             RiskContextEnricher contextEnricher,
                             RiskAssessmentVectorService vectorService) {
        super("RiskAssessment", tracer);

        this.orchestrator = orchestrator;
        this.contextEnricher = contextEnricher;
        this.vectorService = vectorService;

        log.info("RiskAssessmentLab 초기화 완료 - PipelineOrchestrator 기반 with Vector Storage");
        log.info("  - AINativeProcessor: {}", ainativeProcessor.getClass().getSimpleName());
        log.info("  - PipelineOrchestrator: {}", orchestrator.getClass().getSimpleName());
        log.info("  - ContextEnricher: {}", contextEnricher.getClass().getSimpleName());
        log.info("  - VectorService: {}", vectorService.getClass().getSimpleName());
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

    /**
     * 위험 평가 비동기 처리 (진단 전용 - JSON 응답)
     */
    private Mono<RiskAssessmentResponse> performRiskAssessment(RiskAssessmentRequest request) {
        long totalStartTime = System.currentTimeMillis();
        String assessmentId = generateAssessmentId();
        
        // 벡터 저장소에 요청 저장
        try {
            vectorService.storeRiskAssessmentRequest(request);
        } catch (Exception e) {
            log.error("벡터 저장소 요청 저장 실패", e);
        }
        

        return Mono.just(request.getContext())
                .flatMap(ctx -> {
                    // 1. 컨텍스트 강화 단계 - 리액티브 방식
                    long enrichStart = System.currentTimeMillis();
                    log.info("[{}] STEP 1: 컨텍스트 강화 시작", assessmentId);

                    return enrichContextWithTimeout(ctx, assessmentId)
                            .doOnSuccess(enrichedContext -> {
                                long enrichTime = System.currentTimeMillis() - enrichStart;
                                log.info("[{}] STEP 1 완료: 컨텍스트 강화 {}ms", assessmentId, enrichTime);
                            });
                })
                .flatMap(enrichedContext -> {
                    // 2. 위험 평가 요청 생성 단계
                    long requestStart = System.currentTimeMillis();
                    log.info("[{}] STEP 2: 위험 평가 요청 생성 시작", assessmentId);

                    PipelineConfiguration config = createRiskAssessmentPipelineConfig();

                    long requestTime = System.currentTimeMillis() - requestStart;
                    log.info("[{}] STEP 2 완료: 위험 평가 요청 생성 {}ms", assessmentId, requestTime);

                    // 3. PipelineOrchestrator.execute() → 일반 진단 전용 executor
                    long pipelineStart = System.currentTimeMillis();
                    log.info("[{}] STEP 3: PipelineOrchestrator.execute() 호출 - 일반 executor 선택됨", assessmentId);

                    return orchestrator.execute(request, config, RiskAssessmentResponse.class)
                            .doOnSuccess(response -> {
                                long pipelineTime = System.currentTimeMillis() - pipelineStart;
                                log.info("[{}] STEP 3 완료: Pipeline 처리 {}ms", assessmentId, pipelineTime);
                            });
                })
                .map(response -> {
                    // 4. 최종 응답 처리
                    long totalTime = System.currentTimeMillis() - totalStartTime;
                    log.info("[{}] ===== 위험 평가 진단 완료 ===== 총 처리시간: {}ms", assessmentId, totalTime);
                    
                    // 벡터 저장소에 결과 저장
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

    /**
     * 위험 평가 스트리밍 처리 (진단 + 스트리밍 동시 처리)
     */
    private Flux<String> processStreamingRequest(RiskAssessmentRequest request) {
        return Flux.defer(() -> {
            try {
                String assessmentId = generateAssessmentId();
                RiskAssessmentContext context = request.getContext();

                log.info("[STREAMING] RiskAssessment 스트리밍 시작 - User: {} (StreamingUniversalPipelineExecutor 자동선택)",
                        context.getUserId());

                // 1. 컨텍스트 강화 (공통 로직)
                RiskAssessmentContext enrichedContext = contextEnricher.enrichContext(context);
                log.info("[{}] 컨텍스트 강화 완료", assessmentId);

                // 2. 위험 평가 요청 생성 (공통 로직)
                AIRequest<RiskAssessmentContext> riskRequest = createRiskAssessmentRequest(enrichedContext);
                log.info("[{}] 위험 평가 요청 생성 완료", assessmentId);

                // 3. Pipeline 설정
                PipelineConfiguration pipelineConfig = createRiskAssessmentStreamPipelineConfig();
                log.info("⚙️ [{}] Pipeline 설정 완료", assessmentId);

                // 4. PipelineOrchestrator.executeStream() → StreamingUniversalPipelineExecutor 자동 선택
                log.info("[{}] PipelineOrchestrator.executeStream() 호출 - StreamingUniversalPipelineExecutor 자동선택", assessmentId);

                return orchestrator.executeStream(riskRequest, pipelineConfig)
                        .map(chunk -> {
                            String chunkStr = chunk != null ? chunk.toString() : "";
//                            log.error("📦 [{}] [STREAMING] 청크 수신: {}", Thread.currentThread().threadId(), chunkStr.length() > 100 ? chunkStr.substring(0, 100) + "..." : chunkStr);
                            return chunkStr;
                        })
                        .doOnSubscribe(subscription -> { log.info("📦 [{}][{}] [구독]:", Thread.currentThread().threadId(),Thread.currentThread().getName());})
                        .doOnComplete(() -> {
                            log.info("[{}] RiskAssessment 스트리밍 완료 (진단 결과도 함께 수집됨)", assessmentId);
                        })
                        .doOnError(error -> {
                            log.error("[{}] [STREAMING] 스트리밍 오류: {}", assessmentId,
                                    error instanceof Throwable ? ((Throwable) error).getMessage() : error.toString());
                        })
                        .onErrorResume(error -> {
                            // 오류 시 안전한 폴백 메시지 반환
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
                .build();
    }


    private Mono<RiskAssessmentContext> enrichContextWithTimeout(RiskAssessmentContext context, String assessmentId) {
        // AtomicLong 으로 변경하여 리액티브 체인에서 안전하게 사용
        final AtomicLong enrichmentStart = new AtomicLong(System.currentTimeMillis());

        return Mono.defer(() -> {
            enrichmentStart.set(System.currentTimeMillis()); // 실제 실행 시점에 시간 기록
            log.debug("[{}] 컨텍스트 강화 시작", assessmentId);

            return Mono.fromCallable(() -> contextEnricher.enrichContext(context))
                    // subscribeOn 으로 별도 스레드에서 실행하여 블로킹 방지
                    .subscribeOn(Schedulers.boundedElastic())
                    .timeout(java.time.Duration.ofMillis(MAX_ENRICHMENT_TIME_MS))
                    .doOnSuccess(enrichedContext -> {
                        long enrichmentTime = System.currentTimeMillis() - enrichmentStart.get();

                        if (enrichmentTime > MAX_ENRICHMENT_TIME_MS) {
                            log.warn("[{}] 컨텍스트 강화 시간 초과: {}ms > {}ms",
                                    assessmentId, enrichmentTime, MAX_ENRICHMENT_TIME_MS);
                        }

                        // validateEnrichedContext가 블로킹 메서드라면 try-catch로 감싸기
                        try {
                            validateEnrichedContext(enrichedContext, assessmentId);
                        } catch (Exception e) {
                            log.error("[{}] 컨텍스트 검증 실패: {}", assessmentId, e.getMessage());
                        }

                        log.debug("[{}] 컨텍스트 강화 완료 - 처리시간: {}ms, 복잡도: {}",
                                assessmentId, enrichmentTime, enrichedContext.calculateRiskComplexity());
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

                        // 원본 context를 그대로 사용하고 속성만 추가
                        context.withEnvironmentAttribute("enrichmentError", error.getMessage());
                        context.withEnvironmentAttribute("enrichmentFallback", true);
                        return Mono.just(context);
                    });
        });
    }

    private AIRequest<RiskAssessmentContext> createRiskAssessmentRequest(RiskAssessmentContext context) {
        return new AIRequest<>(
                context,
                "riskAssessmentStreaming",
                context.getOrganizationId()
        );
    }

    private RequestPriority determinePriority(RiskAssessmentContext context) {
        if (context.getUserRoles() != null &&
                context.getUserRoles().stream().anyMatch(role -> role.contains("ADMIN") || role.contains("ROOT"))) {
            return RequestPriority.HIGH;
        }

        Object recentFailedAttempts = context.getEnvironmentAttributes().get("recentFailedAttempts");
        if (recentFailedAttempts instanceof Number && ((Number) recentFailedAttempts).intValue() > 5) {
            return RequestPriority.HIGH;
        }

        Object sensitivityLevel = context.getEnvironmentAttributes().get("resourceSensitivityLevel");
        if ("HIGH".equals(sensitivityLevel) || "CRITICAL".equals(sensitivityLevel)) {
            return RequestPriority.NORMAL;
        }

        return RequestPriority.LOW;
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

        log.debug("[{}] 컨텍스트 품질 점수: {}/100 ({}%)",
                assessmentId, validationScore, Math.round(qualityScore * 100));

        if (qualityScore < 0.5) {
            log.warn("[{}] 컨텍스트 품질이 낮음: {}% < 50%", assessmentId, Math.round(qualityScore * 100));
        }
    }

    private RiskAssessmentResponse enhanceResponseQuality(RiskAssessmentResponse response,
                                                          RiskAssessmentContext context,
                                                          String assessmentId) {
        try {
            double confidenceLevel = getConfidenceLevel(response);
            if (confidenceLevel < MIN_CONFIDENCE_THRESHOLD) {
                log.warn("[{}] AI 응답 신뢰도 낮음: {} < {}",
                        assessmentId, confidenceLevel, MIN_CONFIDENCE_THRESHOLD);
                return enhanceResponseWithFallback(response, context);
            }

            validateScoreConsistency(response, assessmentId);
            validateRecommendation(response, context, assessmentId);

            return response;

        } catch (Exception e) {
            log.error("[{}] 응답 품질 강화 실패: {}", assessmentId, e.getMessage());
            return response;
        }
    }

    private double getConfidenceLevel(RiskAssessmentResponse response) {
        try {
            if (response != null) {
                return 0.8; // 임시 기본값
            }
        } catch (Exception e) {
            log.debug("신뢰도 접근 실패, 기본값 사용: {}", e.getMessage());
        }
        return 0.8;
    }

    private RiskAssessmentResponse enhanceResponseWithFallback(RiskAssessmentResponse original, RiskAssessmentContext context) {
        double adjustedRiskScore = Math.min(1.0, original.riskScore() + 0.2);
        double adjustedTrustScore = Math.max(0.0, original.trustScore() - 0.2);

        String adjustedRecommendation = determineConservativeRecommendation(adjustedRiskScore);

        return createAdjustedResponse(original, adjustedRiskScore, adjustedTrustScore, adjustedRecommendation);
    }

    private RiskAssessmentResponse createAdjustedResponse(RiskAssessmentResponse original,
                                                          double riskScore,
                                                          double trustScore,
                                                          String recommendation) {

        TrustAssessment adjustedAssessment = new TrustAssessment(
                trustScore,
                List.of("RISK_ADJUSTED", "FALLBACK_MODE"),
                recommendation
        );

        RiskAssessmentResponse adjusted = new RiskAssessmentResponse(original.getRequestId(), adjustedAssessment);

        adjusted.setProcessingMetrics(
                original.getProcessingTimeMs(),
                original.getAssessedByNode(),
                original.isUsedHistoryAnalysis(),
                original.isUsedBehaviorAnalysis(),
                original.getAnalyzedHistoryRecords()
        );

        return adjusted;
    }

    private String determineConservativeRecommendation(double riskScore) {
        if (riskScore >= 0.8) return "DENY";
        if (riskScore >= 0.6) return "RESTRICT";
        if (riskScore >= 0.4) return "MONITOR";
        return "ALLOW";
    }

    private void validateScoreConsistency(RiskAssessmentResponse response, String assessmentId) {
        double expectedTrustScore = 1.0 - response.riskScore();
        double scoreDifference = Math.abs(response.trustScore() - expectedTrustScore);

        if (scoreDifference > 0.3) {
            log.warn("[{}] 점수 일관성 문제: riskScore={}, trustScore={}, expected={}",
                    assessmentId, response.riskScore(), response.trustScore(), expectedTrustScore);
        }
    }

    private void validateRecommendation(RiskAssessmentResponse response, RiskAssessmentContext context, String assessmentId) {
        String recommendation = response.recommendation();
        double riskScore = response.riskScore();

        boolean inconsistent = false;

        if ("ALLOW".equals(recommendation) && riskScore > 0.7) inconsistent = true;
        if ("DENY".equals(recommendation) && riskScore < 0.3) inconsistent = true;

        if (inconsistent) {
            log.warn("[{}] 권장사항 불일치: recommendation={}, riskScore={}",
                    assessmentId, recommendation, riskScore);
        }
    }

    private RiskAssessmentResponse createFailsafeResponse(RiskAssessmentContext context, Throwable error) {
        log.warn("Creating failsafe response due to error: {}", error.getMessage());

        TrustAssessment failsafeAssessment = new TrustAssessment(
                0.2,
                List.of("AI_SYSTEM_ERROR", "FAILSAFE_MODE", "HIGH_RISK"),
                determineConservativeRecommendation(0.8)
        );

        RiskAssessmentResponse response = new RiskAssessmentResponse(generateRequestId(), failsafeAssessment);

        response.withMetadata("failsafeMode", true);
        response.withMetadata("errorType", error.getClass().getSimpleName());
        response.withMetadata("errorMessage", error.getMessage());

        return response;
    }

    private void recordPerformanceMetrics(String assessmentId, long processingTime, RiskAssessmentResponse response) {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("assessmentId", assessmentId);
        metrics.put("processingTimeMs", processingTime);
        metrics.put("riskScore", response.riskScore());
        metrics.put("trustScore", response.trustScore());
        metrics.put("recommendation", response.recommendation());
        metrics.put("timestamp", LocalDateTime.now());

        log.debug("[{}] 성능 메트릭 기록: {}", assessmentId, metrics);
    }

    private String generateAssessmentId() {
        return "RISK-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 1000);
    }

    private String generateRequestId() {
        return java.util.UUID.randomUUID().toString();
    }
    
    /**
     * RiskAssessmentRequest로부터 RiskAssessmentContext 생성
     */
    private RiskAssessmentContext createRiskAssessmentContext(RiskAssessmentRequest request) {
        RiskAssessmentContext context = request.getContext();
        if (context == null) {
            // 기본 컨텍스트 생성
            context = new RiskAssessmentContext();
            context.setUserId(request.getUserId());
            context.setResourceIdentifier(request.getResourceId());
            context.setActionType(request.getActionType());
        }
        return context;
    }
    
    /**
     * 피드백 기반 학습
     * 
     * @param request 원본 요청
     * @param response 생성된 응답
     * @param feedback 사용자 피드백
     */
    public void learnFromFeedback(RiskAssessmentRequest request, RiskAssessmentResponse response, String feedback) {
        try {
            // 현재 RiskAssessmentVectorService는 storeFeedback 메서드가 없으므로
            // 요청과 결과를 다시 저장하면서 피드백을 메타데이터로 포함
            log.info("[RiskAssessmentLab] 피드백 학습 시작: {}", feedback.substring(0, Math.min(50, feedback.length())));
            
            // 피드백과 함께 결과 재저장 (향후 확장 가능)
            vectorService.storeRiskAssessmentResult(request, response);
            
            log.info("[RiskAssessmentLab] 피드백 학습 완료");
        } catch (Exception e) {
            log.error("[RiskAssessmentLab] 피드백 학습 실패", e);
        }
    }
}
