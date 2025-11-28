package io.contexa.contexacore.autonomous.security.processor;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1FastFilterStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer3ExpertStrategy;
import io.contexa.contexacore.hcad.engine.ZeroTrustDecisionEngine;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Cold Path 이벤트 처리기 (3-Tier AI 분석)
 *
 * HCAD 유사도가 낮은(≤ 0.70) 요청을 3단계 AI로 분석합니다.
 *
 * 핵심 설계:
 * - Layer 1 (0.55 < similarity ≤ 0.70): TinyLlama LLM 빠른 분석 (20-50ms, $0.0001/req)
 * - Layer 2 (0.40 < similarity ≤ 0.55): Llama3.1:8b LLM 상세 분석 (100-300ms, $0.001/req)
 * - Layer 3 (similarity ≤ 0.40): Claude Sonnet LLM 전문가 분석 (1-5s, $0.02/req)
 *
 * 최적화 (2025-01):
 * - HOT Path 90% (similarity > 0.70) → HCAD만으로 충분
 * - COLD Path 10% (similarity ≤ 0.70) → AI 실시간 맥락 분석
 * - Layer 1: 6% 요청 (빠른 AI 검증)
 * - Layer 2: 3% 요청 (중급 AI 분석)
 * - Layer 3: 1% 요청 (전문가 AI 분석)
 *
 * 처리 흐름:
 * 1. riskScore → similarityScore 역변환 (VectorSimilarityHandler에서 이미 1회 변환됨)
 * 2. 유사도 기반 Layer 결정 (determineStartLayer)
 * 3. Tier별 AI 전략 실행 (Layer1/2/3Strategy)
 * 4. Zero Trust 대응 결정 및 실행
 * 5. SOAR 인시던트 생성 (필요시)
 *
 * @author contexa Platform
 * @since 2.0
 */
@Slf4j
@RequiredArgsConstructor
public class ColdPathEventProcessor implements IPathProcessor {
    
    private final RedisTemplate<String, Object> redisTemplate;
    private final Layer1FastFilterStrategy layer1Strategy;
    private final Layer2ContextualStrategy layer2Strategy;
    private final Layer3ExpertStrategy layer3Strategy;
    private final ZeroTrustDecisionEngine zeroTrustDecisionEngine;

    private static final String THREAT_HISTORY_PREFIX = "threat_history:";
    
    private final AtomicLong processedCount = new AtomicLong(0);
    private final AtomicLong totalProcessingTime = new AtomicLong(0);
    private volatile long lastProcessedTimestamp = 0;

    @Value("${security.plane.agent.similarity-threshold:0.70}")
    private double hotThreshold;  // HOT Path 임계값
    @Value("${security.plane.agent.layer1-threshold:0.55}")
    private double layer1Threshold;  // Layer 1 임계값
    @Value("${security.plane.agent.layer2-threshold:0.40}")
    private double layer2Threshold;  // Layer 2 임계값
    @Value("${security.coldpath.confidence.layer1-base:0.5}")
    private double layer1BaseConfidence;
    @Value("${security.coldpath.confidence.layer2-base:0.6}")
    private double layer2BaseConfidence;
    @Value("${security.coldpath.confidence.layer3-base:0.7}")
    private double layer3BaseConfidence;

    /**
     * Cold Path 이벤트 처리: 계층적 AI 분석을 통한 상세 위험도 평가
     *
     * Comprehensive Risk Score (riskScore): 다차원 위험도 종합 점수
     * 구성 요소:
     * 1. Vector Similarity Risk: HCAD 필터의 벡터 유사도 기반 위험도 (1.0 - similarity)
     * 2. AI Analysis Risk: VectorSimilarityHandler의 AI 분석 결과
     * 3. Session Fingerprint Risk: 세션 지문 불일치로 인한 위험도
     *
     * 범위:
     * - 0.0 ~ 0.3: Low Risk (정상 행동 범위)
     * - 0.3 ~ 0.7: Medium Risk (주의 필요)
     * - 0.7 ~ 1.0: High Risk (Cold Path AI 분석 필수)
     *
     * 처리 경로:
     * - Layer 1 (Fast Filter): riskScore < 0.3 - 98% 조기 종료
     * - Layer 2 (Contextual): 0.3 <= riskScore < 0.7 - 1.8% 중간 분석
     * - Layer 3 (Expert): riskScore >= 0.7 - 0.2% 상세 분석
     *
     * @param event 보안 이벤트
     * @param riskScore Comprehensive Risk Score (0.0 ~ 1.0)
     * @return ProcessingResult (분석 결과, 위협 수준, 권장 조치 포함)
     */
    @Override
    public ProcessingResult processEvent(SecurityEvent event, double riskScore) {
        long startTime = System.currentTimeMillis();
        
        try {
            String userId = event.getUserId();
            if (userId == null) {
                log.warn("Cold Path: userId가 없는 이벤트 - eventId: {}", event.getEventId());
                return ProcessingResult.failure(
                    ProcessingResult.ProcessingPath.COLD_PATH,
                    "Missing userId"
                );
            }
            
            log.info("Cold Path 계층적 AI 진단 시작 - userId: {}, eventId: {}, riskScore: {}", 
                    userId, event.getEventId(), riskScore);
            
            // ProcessingResult 생성
            ProcessingResult result = ProcessingResult.builder()
                    .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                    .currentRiskLevel(riskScore)
                    .aiAnalysisPerformed(true)
                    .success(true)
                    .build();

            // 1. AI Layer 진단 실행 (단일 실행)
            ThreatAnalysisResult analysisResult = performTieredAIAnalysis(event, riskScore);

            // 2. AI 결과를 ZeroTrustDecisionEngine에 전달하여 최종 결정 (순차 실행)
            CompletableFuture<Void> zeroTrustFuture = CompletableFuture.completedFuture(null);
            if (zeroTrustDecisionEngine != null) {
                zeroTrustFuture = zeroTrustDecisionEngine.makeDecision(event, analysisResult)
                        .thenAccept(zeroTrustDecision -> {
                            // ZeroTrustDecision 결과를 ProcessingResult에 통합
                            result.addAnalysisData("zeroTrustDecision", zeroTrustDecision);
                            result.addAnalysisData("trustScore", zeroTrustDecision.getTrustScore());
                            result.addAnalysisData("zeroTrustRiskLevel", zeroTrustDecision.getRiskLevel());
                            result.addAnalysisData("accessRecommendations", zeroTrustDecision.getRecommendations());
                            result.addAnalysisData("zeroTrustPrinciples", zeroTrustDecision.getZeroTrustPrinciples());

                            log.info("ZeroTrust 결정 완료 - userId: {}, action: {}, trustScore: {}, riskLevel: {}",
                                    userId, zeroTrustDecision.getFinalAction(),
                                    String.format("%.3f", zeroTrustDecision.getTrustScore()),
                                    zeroTrustDecision.getRiskLevel());
                        })
                        .exceptionally(ex -> {
                            log.error("ZeroTrust 결정 실패 - userId: {}, eventId: {}", userId, event.getEventId(), ex);
                            return null;
                        });
            }

            // ZeroTrust 결정 완료 대기
            try {
                zeroTrustFuture.get();
            } catch (Exception e) {
                log.error("ZeroTrust 결정 대기 실패 - eventId: {}", event.getEventId(), e);
            }

            double threatAdjustment = calculateThreatAdjustment(analysisResult);
            result.setThreatScoreAdjustment(threatAdjustment);

            result.addAnalysisData("aiAssessment", analysisResult);
            result.addAnalysisData("threatLevel", analysisResult.getThreatLevel());
            result.addAnalysisData("strategies", analysisResult.getStrategiesUsed());

            // 분석 레벨 기록 (항상 계층적 분석 사용)
            result.setAiAnalysisLevel(analysisResult.getAnalysisDepth());

            // 비동기로 감사 필수 데이터만 기록
            final String finalUserId = userId;
            final SecurityEvent finalEvent = event;
            final ThreatAnalysisResult finalAnalysisResult = analysisResult;

            CompletableFuture.runAsync(() -> {
                recordThreatHistory(finalUserId, finalEvent.getEventType().toString(), finalAnalysisResult.getFinalScore());
            }).exceptionally(ex -> {
                log.error("Failed to record threat history for user: {}, eventId: {}",
                    userId, event.getEventId(), ex);
                return null;
            });
            
            // 통계 업데이트
            long processingTime = System.currentTimeMillis() - startTime;
            updateStatistics(processingTime);
            
            // 결과에 처리 시간 설정
            result.setProcessingTimeMs(processingTime);
            result.setProcessedAt(LocalDateTime.now());
            result.setStatus(ProcessingResult.ProcessingStatus.SUCCESS);
            
            log.info("Cold Path AI 진단 완료 - userId: {}, finalScore: {}, threatLevel: {}, 시간: {}ms", 
                    userId, analysisResult.getFinalScore(), analysisResult.getThreatLevel(), processingTime);
            
            return result;
            
        } catch (Exception e) {
            log.error("Cold Path 처리 실패 - eventId: {}", event.getEventId(), e);
            return ProcessingResult.failure(
                ProcessingResult.ProcessingPath.COLD_PATH,
                "AI analysis failed: " + e.getMessage()
            );
        }
    }

    /**
     * 위협 히스토리 기록
     */
    private void recordThreatHistory(String userId, String eventType, double score) {
        try {
            String historyKey = THREAT_HISTORY_PREFIX + userId;
            
            Map<String, Object> entry = new HashMap<>();
            entry.put("timestamp", LocalDateTime.now().toString());
            entry.put("eventType", eventType);
            entry.put("score", score);
            entry.put("processedBy", "ColdPath-AI");
            
            redisTemplate.opsForList().leftPush(historyKey, entry);
            redisTemplate.opsForList().trim(historyKey, 0, 99); // 최근 100개만 유지
            redisTemplate.expire(historyKey, Duration.ofDays(30));
            
        } catch (Exception e) {
            log.error("히스토리 기록 실패 - userId: {}", userId, e);
        }
    }
    

    /**
     * MEDIUM FIX: 계층적 AI 분석 수행 (세션 지문 검증 통합)
     *
     * 계층적 분석 전략:
     * - HOT Path (similarity > 0.85): Layer 1에서 빠른 처리 (98% 케이스)
     * - WARM Path (0.6 < similarity ≤ 0.85): Layer 2에서 상세 분석 (1.8% 케이스)
     * - COLD Path (similarity ≤ 0.6): Layer 3에서 전문가 분석 (0.2% 케이스)
     *
     * 추가 기능: 세션 지문 검증 통합 (performAIAnalysis()와 일관성)
     * - 세션 관련 이벤트에 대한 지문 분석
     * - 이상 징후 탐지 및 위험 점수 조정
     *
     * 메인 라우팅 시스템(RoutingDecisionHandler)과 완전히 동일한 임계값 사용
     *
     * @param event 보안 이벤트
     * @param riskScore 초기 위험도 점수 (0.0~1.0)
     * @return 계층적 AI 분석 결과
     */
    private ThreatAnalysisResult performTieredAIAnalysis(SecurityEvent event, double riskScore) {
        ThreatAnalysisResult result = new ThreatAnalysisResult();
        result.setBaseScore(riskScore);

        long startTime = System.currentTimeMillis();

        try {
            // 유사도 기반 시작 Layer 결정 (메인 라우팅과 동일)
            int startLayer = determineStartLayer(riskScore, event);
            log.info("계층적 분석 시작 - riskScore: {}, startLayer: {}, eventId: {}",
                    riskScore, startLayer, event.getEventId());

            // Layer 1: 초고속 필터링 (20-50ms) - HOT Path (similarity > 0.85)
            if (startLayer <= 1 && layer1Strategy != null) {
                log.debug("Layer 1 초고속 필터링 시작 - eventId: {}", event.getEventId());

                ThreatAssessment layer1Assessment = layer1Strategy.evaluate(event);
                log.info("Layer 1 평가: riskScore={}, confidence={}, threatLevel={}",
                        layer1Assessment.getRiskScore(), layer1Assessment.getConfidence(),
                        layer1Assessment.getThreatLevel());

                // Layer1의 새로운 riskScore 기반 동적 조기 종료 임계값
                // Layer1이 재평가한 위험도를 신뢰하여, 더 정확한 임계값 계산
                double requiredConfidence = calculateRequiredConfidence(layer1Assessment.getRiskScore(), 1);

                // Layer1에서 확실한 결정이 나오면 여기서 종료
                if (layer1Assessment.getConfidence() > requiredConfidence) {
                    result.setFinalScore(layer1Assessment.getRiskScore());
                    result.setThreatLevel(layer1Assessment.getThreatLevel());
                    result.setConfidence(layer1Assessment.getConfidence());
                    result.addIndicators(layer1Assessment.getIndicators());
                    result.addRecommendedActions(layer1Assessment.getRecommendedActions());
                    result.setAnalysisDepth(1); // Layer1에서 종료

                    log.info("Layer 1에서 처리 완료 (98% 케이스) - confidence: {}/{}, 시간: {}ms",
                            layer1Assessment.getConfidence(), requiredConfidence,
                            System.currentTimeMillis() - startTime);

                    return result;
                }
            }

            // Layer 2: 컨텍스트 분석 (100-300ms) - riskScore < 0.9일 때만
            if (startLayer <= 2 && layer2Strategy != null) {
                log.debug("Layer 2 컨텍스트 분석 시작 - eventId: {}", event.getEventId());

                ThreatAssessment layer2Assessment = layer2Strategy.evaluate(event);
                log.info("Layer 2 평가: riskScore={}, confidence={}, threatLevel={}",
                        layer2Assessment.getRiskScore(), layer2Assessment.getConfidence(),
                        layer2Assessment.getThreatLevel());

                // Layer2의 새로운 riskScore 기반 동적 조기 종료 임계값
                // Layer2가 재평가한 위험도를 신뢰하여, 더 정확한 임계값 계산
                double requiredConfidenceL2 = calculateRequiredConfidence(layer2Assessment.getRiskScore(), 2);

                // Layer2에서 확신도가 높으면 여기서 종료
                if (layer2Assessment.getConfidence() > requiredConfidenceL2) {
                    result.setFinalScore(layer2Assessment.getRiskScore());
                    result.setThreatLevel(layer2Assessment.getThreatLevel());
                    result.setConfidence(layer2Assessment.getConfidence());
                    result.addIndicators(layer2Assessment.getIndicators());
                    result.addRecommendedActions(layer2Assessment.getRecommendedActions());
                    result.setAnalysisDepth(2); // Layer2에서 종료

                    log.info("Layer 2에서 처리 완료 (1.8% 케이스) - confidence: {}/{}, 시간: {}ms",
                            layer2Assessment.getConfidence(), requiredConfidenceL2,
                            System.currentTimeMillis() - startTime);

                    return result;
                }
            }

            // Layer 3: 전문가 분석 (1-5초) - 가장 복잡한 0.2% 케이스
            if (layer3Strategy != null) {
                log.debug("Layer 3 전문가 분석 시작 - eventId: {}", event.getEventId());

                ThreatAssessment layer3Assessment = layer3Strategy.evaluate(event);
                log.info("Layer 3 평가: riskScore={}, confidence={}, threatLevel={}",
                        layer3Assessment.getRiskScore(), layer3Assessment.getConfidence(),
                        layer3Assessment.getThreatLevel());

                result.setFinalScore(layer3Assessment.getRiskScore());
                result.setThreatLevel(layer3Assessment.getThreatLevel());
                result.setConfidence(layer3Assessment.getConfidence());
                result.addIndicators(layer3Assessment.getIndicators());
                result.addRecommendedActions(layer3Assessment.getRecommendedActions());
                result.setAnalysisDepth(3); // Layer3에서 종료

                log.info("Layer 3에서 최종 처리 완료 (0.2% 케이스) - 시간: {}ms",
                        System.currentTimeMillis() - startTime);

                return result;
            }
            return result;

        } catch (Exception e) {
            log.error("계층적 AI 분석 실패 - eventId: {}, riskScore를 fallback으로 사용", event.getEventId(), e);
            // CRITICAL FIX: 기존 riskScore (VectorSimilarity 기반) 재사용
            // 하드코딩 대신 사용자의 실제 위험도를 fallback으로 사용
            result.setFinalScore(riskScore);  // 이미 계산된 riskScore 사용

            // riskScore 기반 ThreatLevel 동적 결정
            if (riskScore >= 0.8) {
                result.setThreatLevel(ThreatAssessment.ThreatLevel.CRITICAL);
            } else if (riskScore >= 0.6) {
                result.setThreatLevel(ThreatAssessment.ThreatLevel.HIGH);
            } else if (riskScore >= 0.4) {
                result.setThreatLevel(ThreatAssessment.ThreatLevel.MEDIUM);
            } else {
                result.setThreatLevel(ThreatAssessment.ThreatLevel.LOW);
            }

            result.setConfidence(0.3);  // AI 실패 시 낮은 신뢰도
            result.setAnalysisDepth(0);  // AI 분석 실패 표시
            return result;
        }
    }

    
    /**
     * HCAD 유사도 기반 시작 Layer 결정 (3-Tier AI 분석)
     *
     * 스케일 정의:
     * - riskScore: 0.0~1.0 (VectorSimilarityHandler에서 계산된 위험도)
     * - similarityScore: 0.0~1.0 (HCAD 벡터 유사도, riskScore의 역)
     *
     * 변환 로직:
     * 1. VectorSimilarityHandler: riskScore = 1.0 - similarityScore (1회 변환)
     * 2. ColdPathEventProcessor: similarityScore = 1.0 - riskScore (역변환으로 복원)
     * → 결과: 원래 HCAD 유사도가 복원됨!
     *
     * Layer 결정 임계값 (2025-01 최적화):
     * - similarity > 0.55 (layer1Threshold) → Layer 1 (TinyLlama, 6% 케이스)
     * - 0.40 < similarity ≤ 0.55 (layer2Threshold) → Layer 2 (Llama3.1, 3% 케이스)
     * - similarity ≤ 0.40 → Layer 3 (Claude Sonnet, 1% 케이스)
     *
     * 참고: similarity > 0.70 (hotThreshold)은 HOT Path로 이미 필터링되어
     * 이 메서드에 도달하지 않음 (RoutingDecisionHandler에서 처리)
     *
     * 예시:
     * - riskScore=0.35 → similarity=0.65 → Layer 1 (빠른 AI 검증)
     * - riskScore=0.52 → similarity=0.48 → Layer 2 (중급 AI 분석)
     * - riskScore=0.75 → similarity=0.25 → Layer 3 (전문가 AI 분석)
     *
     * @param riskScore 위험도 점수 (0.0~1.0)
     * @param event 보안 이벤트
     * @return 시작 Layer (1=Layer1, 2=Layer2, 3=Layer3)
     */
    private int determineStartLayer(double riskScore, SecurityEvent event) {
        // 스케일 검증
        if (riskScore < 0.0 || riskScore > 1.0) {
            log.warn("[ColdPathEventProcessor] Invalid riskScore: {}, clamping to [0.0, 1.0]", riskScore);
            riskScore = Math.max(0.0, Math.min(1.0, riskScore));
        }

        // 유사도 역변환 (0.0~1.0 스케일)
        double similarityScore = 1.0 - riskScore;

        // Layer 결정 (새로운 임계값 사용)
        int layer;
        if (similarityScore > this.layer1Threshold) {
            // 높은 유사도 (> 0.55) - Layer 1에서 TinyLlama 빠른 분석
            layer = 1;
        } else if (similarityScore > this.layer2Threshold) {
            // 중간 유사도 (0.40 < sim ≤ 0.55) - Layer 2에서 Llama3.1 상세 분석
            layer = 2;
        } else {
            // 낮은 유사도 (≤ 0.40) - Layer 3에서 Claude 전문가 분석
            layer = 3;
        }

        // 상세 로깅
        log.info("[ColdPathEventProcessor] Layer 결정: riskScore={} (0-1), similarity={} (0-1), " +
                "thresholds[L1>{}, L2>{}, L3≤{}] → Layer {} 선택, eventId={}",
                String.format("%.3f", riskScore),
                String.format("%.3f", similarityScore),
                String.format("%.2f", this.layer1Threshold),
                String.format("%.2f", this.layer2Threshold),
                String.format("%.2f", this.layer2Threshold),
                layer,
                event.getEventId());

        return layer;
    }
    
    /**
     * 통계 업데이트
     */
    private synchronized void updateStatistics(long processingTime) {
        processedCount.incrementAndGet();
        totalProcessingTime.addAndGet(processingTime);
        lastProcessedTimestamp = System.currentTimeMillis();
    }
    
    @Override
    public ProcessingMode getProcessingMode() {
        return ProcessingMode.AI_ANALYSIS;
    }
    
    @Override
    public String getProcessorName() {
        return "ColdPathEventProcessor-AI";
    }
    
    /**
     * CRITICAL FIX: 위협 점수 조정값 계산 (편차 기반 재설계)
     *
     * 목적:
     * SecurityPlaneAgent가 이 값을 사용하여 Redis의 Threat Score를 업데이트합니다.
     * Redis 공식: newScore = (currentScore * decayFactor) + adjustment
     *
     * 핵심 개선:
     * - finalScore (이벤트 위험도)를 그대로 사용하지 않고 편차(deviation) 계산
     * - 안전한 이벤트 (finalScore < 0.5) → 음수 조정 → 위험도 감소
     * - 위험한 이벤트 (finalScore > 0.5) → 양수 조정 → 위험도 증가
     * - INFO 레벨 신뢰 회복 강화 (0.05 → 0.3)
     *
     * 수정된 공식:
     * adjustment = deviation * confidenceWeight * magnitude
     *
     * - deviation: finalScore - 0.5 (기준점 대비 편차, -0.5 ~ +0.5)
     * - confidenceWeight: AI 예측의 신뢰도 반영 (0.5~1.0)
     * - magnitude: 위협 레벨에 따른 조정 강도 (0.0~1.0)
     *
     * 위협 레벨별 조정 강도:
     * - CRITICAL: 1.0 (매우 위험, 최대 조정)
     * - HIGH: 0.7 (위험, 강한 조정)
     * - MEDIUM: 0.4 (주의, 중간 조정)
     * - LOW: 0.15 (경미, 약한 조정)
     * - INFO: 0.3 (정보성, 신뢰 회복 강화)
     *
     * 예시:
     * - CRITICAL, finalScore=0.9 → deviation=+0.4 → adjustment=+0.34 (위험 증가)
     * - MEDIUM, finalScore=0.5 → deviation=0.0 → adjustment=0.0 (변화 없음)
     * - LOW, finalScore=0.2 → deviation=-0.3 → adjustment=-0.032 (위험 감소)
     * - INFO, finalScore=0.1 → deviation=-0.4 → adjustment=-0.084 (신뢰 회복)
     *
     * @param analysisResult AI 분석 결과
     * @return Threat Score 조정값 (-0.5 ~ +0.5)
     */
    private double calculateThreatAdjustment(ThreatAnalysisResult analysisResult) {
        double finalScore = analysisResult.getFinalScore();
        ThreatAssessment.ThreatLevel level = analysisResult.getThreatLevel();
        double confidence = analysisResult.getConfidence();

        // 모든 Layer가 0-1 스케일 통일 사용
        // 입력 검증만 수행
        if (finalScore < 0.0 || finalScore > 1.0) {
            finalScore = Math.max(0.0, Math.min(1.0, finalScore));
            log.warn("[ColdPathEventProcessor] riskScore 범위 초과로 클램핑: {} → {}",
                    analysisResult.getFinalScore(), finalScore);
        }
        if (confidence < 0.0 || confidence > 1.0) {
            confidence = Math.max(0.0, Math.min(1.0, confidence));
        }

        // 최소 신뢰도 보장 (너무 낮은 confidence는 0.5로 보정)
        double confidenceWeight = Math.max(confidence, 0.5);

        // CRITICAL FIX: 기준점(중립) 대비 편차 계산
        double baseline = 0.5;
        double deviation = finalScore - baseline;  // -0.5 ~ +0.5 (음수=안전, 양수=위험)

        // 위협 레벨별 조정 강도 (CRITICAL 강화)
        double magnitude;
        if (level == null) {
            magnitude = 0.6;
        } else {
            magnitude = switch (level) {
                case CRITICAL -> 2.0;   // 매우 위험 - 강화된 조정 (1.0 → 2.0)
                case HIGH -> 1.2;       // 위험 - 강화된 조정 (0.7 → 1.2)
                case MEDIUM -> 0.6;     // 주의 - 중간 조정 (0.4 → 0.6)
                case LOW -> 0.2;        // 경미 - 약한 조정 (0.15 → 0.2)
                case INFO -> 0.1;       // 정보성 - 최소 조정 (0.3 → 0.1)
            };
        }

        // 최종 조정값 계산 (편차 기반)
        double adjustment = deviation * confidenceWeight * magnitude;

        // CRITICAL FIX: 단일 이벤트 최대 변동량 제한 (v3.1)
        // 기존 -0.8 ~ +0.8 범위는 너무 넓어 233% 점프 가능
        // 안정적인 점진적 변화를 위해 -0.15 ~ +0.15로 제한
        double maxDelta = 0.15;
        adjustment = Math.max(-maxDelta, Math.min(maxDelta, adjustment));

        // 상세 로깅
        log.info("[ColdPathEventProcessor] Threat Score 조정값: level={}, finalScore={}, deviation={}, magnitude={} → adjustment={}",
            level,
            String.format("%.3f", finalScore),
            String.format("%.3f", deviation),
            String.format("%.2f", magnitude),
            String.format("%+.3f", adjustment));  // 부호 포함 출력

        return adjustment;
    }

    /**
     * CRITICAL FIX: 유사도 기반 동적 신뢰도 임계값 계산 (재조정됨)
     *
     * 수학적 원리:
     * - 낮은 유사도(높은 위험도) → 높은 신뢰도 요구 → 더 깊은 분석 필요
     * - 높은 유사도(낮은 위험도) → 낮은 신뢰도 허용 → 조기 종료 가능
     *
     * 스케일 명확화:
     * - riskScore: 0.0~1.0 (HCADFilter에서 계산된 실제 위험도)
     * - confidence: 0.0~1.0 (AI 모델의 예측 신뢰도)
     *
     * Layer별 기본 임계값 (실제 AI confidence 0.6~0.8을 고려하여 조정):
     * - Layer 1 (HOT Path): 0.50 (98% 케이스, 빠른 처리)
     * - Layer 2 (WARM Path): 0.60 (1.8% 케이스, 중간 처리)
     * - Layer 3 (COLD Path): 0.70 (0.2% 케이스, 전문가 분석)
     *
     * 동적 조정 범위:
     * - riskScore가 0.0 → adjustment = 0.0 (안전한 이벤트)
     * - riskScore가 1.0 → adjustment = +0.15 (매우 위험한 이벤트)
     *
     * 최종 임계값 범위:
     * - Layer 1: 0.50~0.65 (riskScore에 따라 15% 변동)
     * - Layer 2: 0.60~0.75 (riskScore에 따라 15% 변동)
     * - Layer 3: 0.70~0.85 (riskScore에 따라 15% 변동)
     *
     * @param riskScore 위험도 점수 (0.0~1.0 스케일, HCADFilter 계산)
     * @param layer 처리 레이어 (1=HOT, 2=WARM, 3=COLD)
     * @return 해당 레이어에서 요구되는 최소 신뢰도 (0.0~1.0)
     */
    private double calculateRequiredConfidence(double riskScore, int layer) {
        // 스케일 정규화: riskScore가 0.0~1.0 범위인지 확인
        if (riskScore < 0.0 || riskScore > 1.0) {
            riskScore = Math.max(0.0, Math.min(1.0, riskScore));
        }

        // Layer별 기본 신뢰도 임계값 (설정 가능, 유의미한 차이)
        double baseConfidence;
        switch (layer) {
            case 1 -> baseConfidence = layer1BaseConfidence; // 기본 0.70 (HOT Path)
            case 2 -> baseConfidence = layer2BaseConfidence; // 기본 0.80 (WARM Path)
            case 3 -> baseConfidence = layer3BaseConfidence; // 기본 0.90 (COLD Path)
            default -> {
                baseConfidence = 0.80;
            }
        }

        // 위험도에 따른 동적 조정 (0.0~1.0 스케일)
        // - riskScore가 높을수록 더 높은 신뢰도 요구
        // - 최대 +0.15까지 증가 (Layer별 15% 변동 범위 확보)
        double riskAdjustment = riskScore * 0.15;

        // 최종 신뢰도 임계값 계산
        double requiredConfidence = baseConfidence + riskAdjustment;

        // 최대값 제한 (0.95 이상은 AI 모델의 실질적 한계)
        requiredConfidence = Math.min(requiredConfidence, 0.95);

        return requiredConfidence;
    }

    @Override
    public ProcessorStatistics getStatistics() {
        ProcessorStatistics stats = new ProcessorStatistics();
        stats.setProcessedCount(processedCount.get());
        
        long count = processedCount.get();
        if (count > 0) {
            stats.setAverageProcessingTime((double) totalProcessingTime.get() / count);
        }
        
        stats.setLastProcessedTimestamp(lastProcessedTimestamp);
        
        return stats;
    }
    
    /**
     * 위협 분석 결과 클래스
     */
    @Getter @Setter
    public static class ThreatAnalysisResult {
        private double baseScore;
        private double finalScore;
        private ThreatAssessment.ThreatLevel threatLevel;
        private double confidence;
        private List<ThreatAssessment> assessments = new ArrayList<>();
        private Set<String> indicators = new HashSet<>();
        private Set<String> recommendedActions = new HashSet<>();
        private int analysisDepth = 0;


        public List<String> getIndicators() { return new ArrayList<>(indicators); }
        public void addIndicator(String indicator) { this.indicators.add(indicator); }
        
        public List<String> getStrategiesUsed() { 
            return assessments.stream()
                .map(ThreatAssessment::getEvaluator)
                .distinct()
                .toList();
        }
        
        public int getAnalysisDepth() {
            // analysisDepth가 명시적으로 설정되었으면 그 값 사용
            if (analysisDepth > 0) return analysisDepth;

            // 그렇지 않으면 assessments 크기로 결정 (하위 호환성)
            if (assessments.size() >= 3) return 3;
            if (assessments.size() >= 2) return 2;
            if (!assessments.isEmpty()) return 1;
            return 0;
        }
        public void addIndicators(List<?> newIndicators) {
            if (newIndicators != null) {
                newIndicators.forEach(i -> this.indicators.add(i.toString()));
            }
        }
        
        public void addRecommendedActions(List<String> actions) {
            if (actions != null) {
                this.recommendedActions.addAll(actions);
            }
        }
        
        public void addRecommendedAction(String action) {
            if (action != null) {
                this.recommendedActions.add(action);
            }
        }

        // ZeroTrustDecisionEngine에서 필요한 메소드들
        public String getLayerExecuted() {
            int depth = getAnalysisDepth();
            if (depth >= 3) return "Layer3";
            if (depth >= 2) return "Layer2";
            if (depth >= 1) return "Layer1";
            return "None";
        }

        public long getProcessingTimeMs() {
            // 실제 처리 시간은 ColdPathEventProcessor 에서 측정
            return 0L;
        }

        public SecurityDecision getFinalDecision() {
            // ThreatLevel을 SecurityDecision.Action으로 변환
            SecurityDecision.Action action;
            switch (threatLevel) {
                case LOW:
                    action = SecurityDecision.Action.ALLOW;
                    break;
                case MEDIUM:
                    action = SecurityDecision.Action.MONITOR;
                    break;
                case HIGH:
                    action = SecurityDecision.Action.INVESTIGATE;
                    break;
                case CRITICAL:
                    action = SecurityDecision.Action.BLOCK;
                    break;
                default:
                    action = SecurityDecision.Action.MONITOR;
            }

            return SecurityDecision.builder()
                .action(action)
                .riskScore(finalScore)
                .confidence(confidence)
                .iocIndicators(new ArrayList<>(indicators))
                .mitigationActions(new ArrayList<>(recommendedActions))
                .reasoning("AI Layer Analysis: " + getLayerExecuted())
                .layer(getLayerExecuted())
                .build();
        }
    }
}