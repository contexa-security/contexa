package io.contexa.contexacore.autonomous.security.processor;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1FastFilterStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer3ExpertStrategy;
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
 * Cold Path 이벤트 처리기 (2-Tier AI 분석)
 *
 * HCAD 유사도가 낮은(≤ 0.70) 요청을 2단계 AI로 분석합니다.
 *
 * 핵심 설계 (2-Tier 구조, 2025-01 리팩토링):
 * - Layer 1: Llama3.1:8b LLM 상세 분석 (300ms, 무료) - 95% 케이스 처리
 * - Layer 2: Claude API LLM 전문가 분석 (5s, 유료) - 5% 케이스 처리
 *
 * 변경 사유:
 * - TinyLlama(1.1B)는 보안 분석에 부적합 (복잡한 컨텍스트 이해 불가)
 * - 대부분 Layer2로 에스컬레이션되어 Layer1 존재 의미 희박
 * - Llama3.1:8b가 95%+ 케이스 처리 가능
 *
 * 처리 흐름:
 * 1. Layer1(Llama3.1:8b) 분석 실행
 * 2. confidence >= 0.8 → 최종 판정
 * 3. confidence < 0.8 → Layer2(Claude) 에스컬레이션
 * 4. LLM riskScore 그대로 반환 (AI Native)
 * 5. Zero Trust 대응 결정 및 실행
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

            // AI Native: LLM riskScore 그대로 사용 (가공 없음)
            double llmRiskScore = calculateThreatAdjustment(analysisResult);
            result.setRiskScore(llmRiskScore);

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
     * 2-Tier AI 분석 Layer 결정
     *
     * 2025-01 리팩토링: 3-Tier → 2-Tier 구조로 단순화
     *
     * 변경 사유:
     * - TinyLlama(1.1B)는 보안 분석에 부적합 (복잡한 컨텍스트 이해 불가)
     * - 대부분 Layer2로 에스컬레이션되어 Layer1 존재 의미 희박
     * - Llama3.1:8b가 95%+ 케이스 처리 가능
     *
     * 새로운 2-Tier 구조:
     * - Layer 1: Llama3.1:8b (기존 Layer2) - 95% 케이스, 300ms
     * - Layer 2: Claude API (기존 Layer3) - 5% 케이스, 5s
     *
     * 스케일 정의:
     * - riskScore: 0.0~1.0 (VectorSimilarityHandler에서 계산된 위험도)
     * - confidence >= 0.8 → Layer1에서 최종 판정
     * - confidence < 0.8 → Layer2 에스컬레이션
     *
     * @param riskScore 위험도 점수 (0.0~1.0)
     * @param event 보안 이벤트
     * @return 시작 Layer (2=Layer2/Llama3.1, 3=Layer3/Claude)
     */
    private int determineStartLayer(double riskScore, SecurityEvent event) {
        // 스케일 검증
        if (riskScore < 0.0 || riskScore > 1.0) {
            log.warn("[ColdPathEventProcessor] Invalid riskScore: {}, clamping to [0.0, 1.0]", riskScore);
            riskScore = Math.max(0.0, Math.min(1.0, riskScore));
        }

        // 2-Tier: 항상 Layer2(Llama3.1)부터 시작
        // Layer1(TinyLlama)은 보안 분석에 부적합하여 사용하지 않음
        int layer = 2;

        // 상세 로깅
        log.info("[ColdPathEventProcessor][2-Tier] Layer 결정: riskScore={} (0-1) → Layer {} 시작 (Llama3.1), eventId={}",
                String.format("%.3f", riskScore),
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
     * AI Native 원칙:
     * - LLM이 반환한 riskScore(0.0~1.0)를 100% 신뢰
     * - deviation, magnitude, maxDelta 등 규칙 기반 조정 완전 제거
     * - ±0.15 제한 완전 제거 (LLM 판단 손실 방지)
     * - 시간 감쇠와 무관하게 독립적으로 동작
     *
     * 이전 방식의 문제점:
     * - LLM이 CRITICAL(0.95) 반환 → ±0.15 제한 → 0.15만 반영 (84% 손실!)
     * - magnitude 곱셈으로 LLM 판단 왜곡
     * - deviation 계산으로 LLM 의도 변형
     *
     * 새로운 방식:
     * - LLM이 CRITICAL(0.95) 반환 → 0.95 그대로 Redis 저장
     * - LLM이 LOW(0.1) 반환 → 0.1 그대로 Redis 저장
     *
     * @param analysisResult AI 분석 결과
     * @return LLM의 riskScore (0.0 ~ 1.0, 가공 없음)
     */
    private double calculateThreatAdjustment(ThreatAnalysisResult analysisResult) {
        double finalScore = analysisResult.getFinalScore();
        ThreatAssessment.ThreatLevel level = analysisResult.getThreatLevel();
        double confidence = analysisResult.getConfidence();

        // 범위 검증만 수행 (0.0~1.0)
        if (finalScore < 0.0 || finalScore > 1.0) {
            double clamped = Math.max(0.0, Math.min(1.0, finalScore));
            log.warn("[ColdPathEventProcessor] riskScore 범위 초과로 클램핑: {} → {}",
                    finalScore, clamped);
            finalScore = clamped;
        }

        // AI Native: LLM riskScore 그대로 반환 (가공 없음)
        log.info("[ColdPathEventProcessor] AI Native riskScore: level={}, riskScore={}, confidence={} → 가공 없이 그대로 사용",
            level,
            String.format("%.3f", finalScore),
            String.format("%.3f", confidence));

        return finalScore;
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