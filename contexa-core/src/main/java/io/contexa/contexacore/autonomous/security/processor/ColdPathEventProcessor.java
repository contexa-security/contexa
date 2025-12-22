package io.contexa.contexacore.autonomous.security.processor;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1FastFilterStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer3ExpertStrategy;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
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

    // AI Native 전환: 고정 임계값 제거
    // - 모든 임계값 판단은 LLM이 수행
    // - Layer 에스컬레이션 결정도 LLM이 수행
    // - 조기 종료 로직 제거 (LLM confidence 100% 신뢰)

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
            result.setRiskScore(analysisResult.getFinalScore());

            result.addAnalysisData("aiAssessment", analysisResult);
            // AI Native v3.1.0: threatLevel -> action
            result.addAnalysisData("action", analysisResult.getAction());
            result.addAnalysisData("strategies", analysisResult.getStrategiesUsed());

            // 분석 레벨 기록 (항상 계층적 분석 사용)
            result.setAiAnalysisLevel(analysisResult.getAnalysisDepth());

            // 비동기로 감사 필수 데이터만 기록
            final String finalUserId = userId;
            final SecurityEvent finalEvent = event;
            final ThreatAnalysisResult finalAnalysisResult = analysisResult;

            CompletableFuture.runAsync(() -> {
                recordThreatHistory(finalUserId, finalEvent.getEventType().toString(), finalAnalysisResult.getFinalScore());
                // AI Native: LLM 분석 결과를 Redis에 저장 (Dual-Write: security:hcad:analysis + security:user:action)
                // 다음 요청에서 HCADAnalysisService와 ZeroTrustSecurityService가 조회
                saveAnalysisToRedis(finalUserId, finalAnalysisResult);
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
            
            log.info("Cold Path AI 진단 완료 - userId: {}, finalScore: {}, action: {}, 시간: {}ms",
                    userId, analysisResult.getFinalScore(), analysisResult.getAction(), processingTime);
            
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
            // AI Native 모니터링: unknown 필드 카운트 (에스컬레이션 결정은 LLM이 수행)
            int unknownCount = countUnknownFields(event);
            if (unknownCount >= 4) {
                log.warn("[ColdPath][AI Native][모니터링] unknown 필드 {}개 감지 - LLM이 데이터 품질 기반으로 판단 예정, eventId: {}",
                    unknownCount, event.getEventId());
            }

            // 유사도 기반 시작 Layer 결정 (메인 라우팅과 동일)
            int startLayer = determineStartLayer(riskScore, event);
            log.info("계층적 분석 시작 - riskScore: {}, startLayer: {}, eventId: {}",
                    riskScore, startLayer, event.getEventId());

            // Layer 1: 초고속 필터링 (20-50ms) - HOT Path
            if (startLayer <= 1 && layer1Strategy != null) {
                log.debug("Layer 1 초고속 필터링 시작 - eventId: {}", event.getEventId());

                ThreatAssessment layer1Assessment = layer1Strategy.evaluate(event);
                // AI Native v3.1.0: threatLevel -> action
                log.info("Layer 1 평가: riskScore={}, confidence={}, action={}, shouldEscalate={}",
                        layer1Assessment.getRiskScore(), layer1Assessment.getConfidence(),
                        layer1Assessment.getAction(), layer1Assessment.isShouldEscalate());

                // AI Native: LLM이 에스컬레이션 필요 여부를 직접 결정
                // 규칙 기반 confidence 비교 완전 제거
                if (!layer1Assessment.isShouldEscalate()) {
                    result.setFinalScore(layer1Assessment.getRiskScore());
                    result.setConfidence(layer1Assessment.getConfidence());
                    result.addIndicators(layer1Assessment.getIndicators());
                    result.addRecommendedActions(layer1Assessment.getRecommendedActions());
                    result.setAnalysisDepth(1); // Layer1에서 종료
                    result.setAction(layer1Assessment.getAction()); // AI Native: LLM action 직접 사용

                    log.info("Layer 1에서 처리 완료 - LLM이 에스컬레이션 불필요 판단, action: {}, 시간: {}ms",
                            layer1Assessment.getAction(), System.currentTimeMillis() - startTime);

                    return result;
                }
            }

            // Layer 2: 컨텍스트 분석 (100-300ms)
            if (startLayer <= 2 && layer2Strategy != null) {
                log.debug("Layer 2 컨텍스트 분석 시작 - eventId: {}", event.getEventId());

                ThreatAssessment layer2Assessment = layer2Strategy.evaluate(event);
                // AI Native v3.1.0: threatLevel -> action
                log.info("Layer 2 평가: riskScore={}, confidence={}, action={}, shouldEscalate={}",
                        layer2Assessment.getRiskScore(), layer2Assessment.getConfidence(),
                        layer2Assessment.getAction(), layer2Assessment.isShouldEscalate());

                // AI Native: LLM이 에스컬레이션 필요 여부를 직접 결정
                // 규칙 기반 confidence 비교 완전 제거
                if (!layer2Assessment.isShouldEscalate()) {
                    result.setFinalScore(layer2Assessment.getRiskScore());
                    result.setConfidence(layer2Assessment.getConfidence());
                    result.addIndicators(layer2Assessment.getIndicators());
                    result.addRecommendedActions(layer2Assessment.getRecommendedActions());
                    result.setAnalysisDepth(2); // Layer2에서 종료
                    result.setAction(layer2Assessment.getAction()); // AI Native: LLM action 직접 사용

                    log.info("Layer 2에서 처리 완료 - LLM이 에스컬레이션 불필요 판단, action: {}, 시간: {}ms",
                            layer2Assessment.getAction(), System.currentTimeMillis() - startTime);

                    return result;
                }
            }

            // Layer 3: 전문가 분석 (1-5초) - 가장 복잡한 0.2% 케이스
            if (layer3Strategy != null) {
                log.debug("Layer 3 전문가 분석 시작 - eventId: {}", event.getEventId());

                ThreatAssessment layer3Assessment = layer3Strategy.evaluate(event);
                // AI Native v3.1.0: threatLevel -> action
                log.info("Layer 3 평가: riskScore={}, confidence={}, action={}",
                        layer3Assessment.getRiskScore(), layer3Assessment.getConfidence(),
                        layer3Assessment.getAction());

                result.setFinalScore(layer3Assessment.getRiskScore());
                result.setConfidence(layer3Assessment.getConfidence());
                result.addIndicators(layer3Assessment.getIndicators());
                result.addRecommendedActions(layer3Assessment.getRecommendedActions());
                result.setAnalysisDepth(3); // Layer3에서 종료
                result.setAction(layer3Assessment.getAction()); // AI Native: LLM action 직접 사용

                log.info("Layer 3에서 최종 처리 완료 (0.2% 케이스) - action: {}, 시간: {}ms",
                        layer3Assessment.getAction(), System.currentTimeMillis() - startTime);

                return result;
            }
            return result;

        } catch (Exception e) {
            log.error("계층적 AI 분석 실패 - eventId: {}, riskScore를 fallback으로 사용", event.getEventId(), e);
            // AI Native: LLM 분석 실패 시에도 규칙 기반 판단 사용하지 않음
            // riskScore는 그대로 사용하되, action은 ESCALATE로 설정하여 상위 검토 필요 표시
            result.setFinalScore(riskScore);

            // AI Native v3.1.0: LLM 분석 실패 시 ESCALATE 설정 (상위 레이어/인간 검토 필요)
            result.setAction("ESCALATE");

            // AI Native: confidence도 NaN으로 설정 (LLM 분석 불가 명시)
            result.setConfidence(Double.NaN);
            result.setAnalysisDepth(0);  // AI 분석 실패 표시
            return result;
        }
    }

    
    /**
     * unknown 필드 카운트 (AI Native 모니터링용)
     *
     * AI Native 원칙:
     * - 이 메서드는 모니터링/로깅 목적으로만 사용
     * - 에스컬레이션 결정은 LLM이 데이터 품질 점수를 보고 판단
     * - 플랫폼은 규칙 기반 에스컬레이션 강제하지 않음
     *
     * @param event 보안 이벤트
     * @return unknown 필드 개수
     */
    private int countUnknownFields(SecurityEvent event) {
        int count = 0;

        // 네트워크 정보
        if (isUnknownValue(event.getSourceIp())) count++;
        if (isUnknownValue(event.getTargetIp())) count++;
        if (isUnknownValue(event.getUserAgent())) count++;

        // 사용자 정보
        if (isUnknownValue(event.getUserId())) count++;
        if (isUnknownValue(event.getSessionId())) count++;

        // 리소스 정보
        if (isUnknownValue(event.getTargetResource())) count++;

        // metadata에서 주요 필드 확인
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null) {
            if (isUnknownValue(getStringFromMap(metadata, "authz.resource"))) count++;
            if (isUnknownValue(getStringFromMap(metadata, "methodClass"))) count++;
        }

        return count;
    }

    private boolean isUnknownValue(String value) {
        return value == null || value.isEmpty() ||
               "unknown".equalsIgnoreCase(value) ||
               "none".equalsIgnoreCase(value) ||
               "N/A".equalsIgnoreCase(value);
    }

    private String getStringFromMap(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value != null ? value.toString() : null;
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
        // AI Native: clamp 연산 제거 - 범위 초과 값도 그대로 로깅하고 사용
        // LLM이 반환한 riskScore를 신뢰
        if (riskScore < 0.0 || riskScore > 1.0) {
            log.warn("[ColdPathEventProcessor][AI Native] 범위 초과 riskScore: {} (가공 없이 사용)", riskScore);
        }

        // AI Native: 시작 Layer 결정도 LLM에 위임 가능
        // 현재는 Layer1부터 시작하여 LLM이 shouldEscalate로 결정
        int layer = 1;

        log.info("[ColdPathEventProcessor][AI Native] Layer 결정: riskScore={} → Layer {} 시작, eventId={}",
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

    /**
     * AI Native: LLM 분석 결과를 Redis에 저장
     *
     * 저장 대상 (2개 키 - Dual-Write for Migration):
     * 1. security:hcad:analysis:{userId} (Hash) - 전체 필드 저장 (Primary)
     * 2. security:user:action:{userId} (String) - action만 저장 (Legacy, 하위 호환성)
     *
     * 다음 요청에서:
     * - HCADAnalysisService: security:hcad:analysis에서 전체 분석 결과 조회
     * - ZeroTrustSecurityService: security:hcad:analysis에서 action 필드 조회 (Dual-Read)
     *
     * Action별 TTL:
     * - BLOCK: TTL 없음 (관리자 해제 필요)
     * - INVESTIGATE: 5분 (자동 복구)
     * - MONITOR: 10분 (자동 복구)
     * - CHALLENGE: 30분 (MFA 성공 시 즉시 해제)
     * - ALLOW: 1시간 (캐시)
     *
     * @param userId 사용자 ID
     * @param analysisResult LLM 분석 결과 (전체 필드)
     */
    private void saveAnalysisToRedis(String userId, ThreatAnalysisResult analysisResult) {
        if (userId == null || userId.isBlank()) {
            return;
        }

        try {
            // AI Native: LLM이 결정한 action을 직접 사용 (deriveAction 제거)
            String action = analysisResult.getAction();
            if (action == null || action.isBlank()) {
                // 폴백: LLM이 action을 반환하지 않은 경우에만 MONITOR 사용
                action = "MONITOR";
                log.warn("[ColdPath][AI Native] LLM action 미반환, 기본값 MONITOR 사용 - userId: {}", userId);
            }

            // Action별 TTL 설정
            Duration ttl = switch (action) {
                case "BLOCK" -> null;  // TTL 없음 - 관리자 해제 필요
                case "INVESTIGATE" -> Duration.ofMinutes(5);
                case "MONITOR" -> Duration.ofMinutes(10);
                case "CHALLENGE" -> Duration.ofMinutes(30);
                default -> Duration.ofHours(1);  // ALLOW 등
            };

            // 1. Primary: security:hcad:analysis:{userId} (Hash - 전체 필드)
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Map<String, Object> fields = new HashMap<>();
            fields.put("action", action);
            fields.put("riskScore", analysisResult.getFinalScore());
            fields.put("confidence", analysisResult.getConfidence());
            // AI Native v3.1.0: threatLevel -> action
            fields.put("action", analysisResult.getAction() != null
                    ? analysisResult.getAction() : "ESCALATE");
            fields.put("isAnomaly", analysisResult.getFinalScore() > 0.5);
            fields.put("threatType", determineThreatType(analysisResult));
            fields.put("threatEvidence", String.join(", ", analysisResult.getIndicators()));
            fields.put("analysisDepth", analysisResult.getAnalysisDepth());
            fields.put("updatedAt", java.time.Instant.now().toString());

            redisTemplate.opsForHash().putAll(analysisKey, fields);
            if (ttl != null) {
                redisTemplate.expire(analysisKey, ttl);
            }

            // 2. Legacy: security:user:action:{userId} (String - action만)
            // Phase A: Rolling Update 및 Rollback 대비 하위 호환성 유지
            String legacyKey = ZeroTrustRedisKeys.userAction(userId);
            if (ttl != null) {
                redisTemplate.opsForValue().set(legacyKey, action, ttl);
            } else {
                redisTemplate.opsForValue().set(legacyKey, action);
            }

            log.info("[ColdPath][AI Native] Analysis saved to Redis (Dual-Write): userId={}, action={}, riskScore={}, confidence={}, ttl={}",
                    userId, action,
                    String.format("%.3f", analysisResult.getFinalScore()),
                    String.format("%.3f", analysisResult.getConfidence()),
                    ttl != null ? ttl.toMinutes() + "m" : "permanent");

        } catch (Exception e) {
            log.error("[ColdPath] Failed to save analysis to Redis: userId={}", userId, e);
        }
    }

    /**
     * 위협 유형 결정 (분석 결과 기반) - AI Native v3.1.0
     */
    private String determineThreatType(ThreatAnalysisResult result) {
        // AI Native: action 기반으로 위협 유형 결정
        if (result.getAction() == null || result.getAction().isBlank()) {
            return "ANALYSIS_INCOMPLETE";
        }
        List<String> indicators = result.getIndicators();
        if (indicators.isEmpty()) {
            return result.getAction() + "_THREAT";
        }
        // 첫 번째 indicator를 위협 유형으로 사용
        return indicators.get(0).toUpperCase().replace(" ", "_");
    }

    @Override
    public ProcessingMode getProcessingMode() {
        return ProcessingMode.AI_ANALYSIS;
    }
    
    @Override
    public String getProcessorName() {
        return "ColdPathEventProcessor-AI";
    }
    
    // AI Native 전환: calculateThreatAdjustment() 메서드 완전 제거
    // - LLM riskScore를 그대로 사용 (가공 없음)
    // - analysisResult.getFinalScore()를 직접 사용

    // AI Native 전환: calculateRequiredConfidence() 메서드 완전 제거
    // - 규칙 기반 confidence 임계값 계산 로직 제거
    // - LLM이 shouldEscalate로 에스컬레이션 필요 여부를 직접 결정
    // - Layer별 baseConfidence, riskAdjustment 규칙 모두 제거

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
        // AI Native v3.1.0: threatLevel 필드 제거, action 필드로 완전 대체
        private double confidence;
        private List<ThreatAssessment> assessments = new ArrayList<>();
        private Set<String> indicators = new HashSet<>();
        private Set<String> recommendedActions = new HashSet<>();
        private int analysisDepth = 0;
        // AI Native: LLM이 직접 결정한 action (v3.1.0: 4개 action 체계)
        // ALLOW, BLOCK, ESCALATE, INVESTIGATE
        private String action;


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

        /**
         * AI Native: 최종 보안 결정 반환
         *
         * v3.1.0 변경사항:
         * - threatLevel 기반 규칙 제거 (AI Native 원칙)
         * - LLM이 결정한 action 필드를 직접 사용
         * - MONITOR/MITIGATE → ESCALATE/BLOCK 매핑 (하위호환)
         *
         * @return SecurityDecision (LLM action 기반)
         */
        public SecurityDecision getFinalDecision() {
            // AI Native v3.3.0: LLM이 결정한 action을 직접 사용 (4개 action)
            SecurityDecision.Action decisionAction;
            String reasoningPrefix;

            if (action != null && !action.isBlank()) {
                // LLM action 직접 매핑 (v3.3.0 4개 action 체계)
                reasoningPrefix = "AI Native Decision: ";
                decisionAction = switch (action.toUpperCase()) {
                    case "ALLOW", "A" -> SecurityDecision.Action.ALLOW;
                    case "BLOCK", "B" -> SecurityDecision.Action.BLOCK;
                    case "CHALLENGE", "C" -> SecurityDecision.Action.CHALLENGE;
                    default -> SecurityDecision.Action.ESCALATE;  // E 및 알 수 없는 action은 ESCALATE
                };
            } else {
                // action이 없으면 분석 미완료 - ESCALATE 설정
                decisionAction = SecurityDecision.Action.ESCALATE;
                reasoningPrefix = "AI Analysis Incomplete: ";
            }

            return SecurityDecision.builder()
                .action(decisionAction)
                .riskScore(finalScore)
                .confidence(confidence)
                .iocIndicators(new ArrayList<>(indicators))
                .mitigationActions(new ArrayList<>(recommendedActions))
                .reasoning(reasoningPrefix + getLayerExecuted())
                .layer(getLayerExecuted())
                .build();
        }
    }
}