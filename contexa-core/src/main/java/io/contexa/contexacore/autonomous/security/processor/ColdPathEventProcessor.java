package io.contexa.contexacore.autonomous.security.processor;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Cold Path 이벤트 처리기 (2-Tier AI 분석)
 *
 * LLM이 분석이 필요하다고 판단한 요청을 2단계 AI로 분석합니다.
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
    private final Layer1ContextualStrategy contextualStrategy;
    private final Layer2ExpertStrategy expertStrategy;

    /**
     * AI Native: Baseline Learning Service (Optional)
     *
     * LLM이 ALLOW + confidence >= 0.7 판정한 정상 요청을 학습하여
     * 다음 요청 분석 시 비교 기준선 제공
     */
    @Autowired(required = false)
    private BaselineLearningService baselineLearningService;

    /**
     * AI Native v3.4.0: Admin Override Service (Optional)
     *
     * LLM이 BLOCK 판정한 요청을 관리자 검토 대기열에 추가
     * 관리자가 검토 후 승인/거부 결정 가능
     *
     * 기준선 오염 방지:
     * - 관리자 승인 시에도 baselineUpdateAllowed=true를 명시적으로 설정해야 기준선 학습
     */
    @Autowired(required = false)
    private AdminOverrideService adminOverrideService;

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
     * 처리 경로 (2-Tier 구조):
     * - Layer 1 (Contextual): LLM 컨텍스트 분석 - 95% 케이스 처리
     *   - shouldEscalate=false: Layer 1에서 최종 판정
     *   - shouldEscalate=true: Layer 2로 에스컬레이션
     * - Layer 2 (Expert): LLM 전문가 분석 - 5% 케이스 처리
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

            // 분석 레벨 기록 (항상 계층적 분석 사용)
            result.setAiAnalysisLevel(analysisResult.getAnalysisDepth());

            // 비동기로 감사 필수 데이터만 기록 + Baseline 학습
            final String finalUserId = userId;
            final SecurityEvent finalEvent = event;
            final ThreatAnalysisResult finalAnalysisResult = analysisResult;

            CompletableFuture.runAsync(() -> {
                // AI Native: LLM 분석 결과를 Redis에 저장 (security:hcad:analysis)
                // 다음 요청에서 HCADAnalysisService와 ZeroTrustSecurityService가 조회
                saveAnalysisToRedis(finalUserId, finalAnalysisResult);

                // AI Native: Baseline Learning
                // LLM이 ALLOW + confidence >= 0.7 판정한 정상 요청을 학습
                // 다음 요청의 Layer1 프롬프트에서 비교 기준선으로 제공
                learnFromAnalysisResult(finalUserId, finalEvent, finalAnalysisResult);
            }).exceptionally(ex -> {
                log.error("Failed to save analysis to Redis: userId={}, eventId={}",
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
     * 계층적 AI 분석 수행 (2-Tier 구조)
     *
     * 계층적 분석 전략 (AI Native):
     * - Layer 1 (Contextual): LLM이 shouldEscalate로 에스컬레이션 필요 여부 결정
     * - Layer 2 (Expert): Layer 1에서 에스컬레이션된 복잡한 케이스 처리
     *
     * 규칙 기반 분기 없음 - LLM이 모든 판단 수행
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
            // AI Native: Layer1부터 시작 (LLM이 shouldEscalate로 상위 Layer 에스컬레이션 결정)
            log.info("계층적 분석 시작 - riskScore: {}, eventId: {}",
                    riskScore, event.getEventId());

            ThreatAssessment layer1Assessment = null;
            if (contextualStrategy != null) {
                log.debug("Layer 1 컨텍스트 분석 시작 - eventId: {}", event.getEventId());

                layer1Assessment = contextualStrategy.evaluate(event);
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

                // AI Native v4.2.0: Layer1 결과를 event metadata에 저장 (Layer2에서 사용)
                event.getMetadata().put("layer1Assessment", layer1Assessment);
                log.debug("Layer 1 결과를 metadata에 저장 - Layer2로 전달");
            }

            // Layer 2: 전문가 분석 (1-5초) - 가장 복잡한 5% 케이스
            if (expertStrategy != null) {
                log.debug("Layer 2 전문가 분석 시작 - eventId: {}", event.getEventId());

                ThreatAssessment layer2Assessment = expertStrategy.evaluate(event);
                // AI Native v3.1.0: threatLevel -> action
                log.info("Layer 2 평가: riskScore={}, confidence={}, action={}",
                        layer2Assessment.getRiskScore(), layer2Assessment.getConfidence(),
                        layer2Assessment.getAction());

                result.setFinalScore(layer2Assessment.getRiskScore());
                result.setConfidence(layer2Assessment.getConfidence());
                result.addIndicators(layer2Assessment.getIndicators());
                result.addRecommendedActions(layer2Assessment.getRecommendedActions());
                result.setAnalysisDepth(2); // Layer2에서 종료
                result.setAction(layer2Assessment.getAction()); // AI Native: LLM action 직접 사용

                log.info("Layer 2에서 최종 처리 완료 (5% 케이스) - action: {}, 시간: {}ms",
                        layer2Assessment.getAction(), System.currentTimeMillis() - startTime);

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

            // AI Native: confidence NaN으로 설정 (LLM 분석 불가 명시)
            result.setConfidence(Double.NaN);
            result.setAnalysisDepth(0);  // AI 분석 실패 표시
            return result;
        }
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
     * 저장 대상:
     * - security:hcad:analysis:{userId} (Hash) - 전체 필드 저장
     *
     * 다음 요청에서:
     * - HCADAnalysisService: security:hcad:analysis에서 전체 분석 결과 조회
     * - ZeroTrustSecurityService: security:hcad:analysis에서 action 필드 조회
     *
     * Action별 TTL (AI Native v3.3.0 - 4개 Action 체계):
     * - BLOCK: TTL 없음 (관리자 해제 필요)
     * - ESCALATE: 5분 (상위 검토 후 자동 복구)
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
                // AI Native: LLM action 미반환 시 ESCALATE (상위 검토 필요)
                action = "ESCALATE";
                log.warn("[ColdPath][AI Native] LLM action 미반환, ESCALATE 설정 - userId: {}", userId);
            }

            // AI Native v3.3.0: 4개 Action 체계 (INVESTIGATE, MONITOR 제거)
            // - BLOCK: TTL 없음 (관리자 해제 필요)
            // - ESCALATE: 5분 (상위 검토 후 자동 복구)
            // - CHALLENGE: 30분 (MFA 성공 시 즉시 해제)
            // - ALLOW: 1시간 (캐시)
            Duration ttl = switch (action.toUpperCase()) {
                case "BLOCK" -> null;  // TTL 없음 - 관리자 해제 필요
                case "ESCALATE" -> Duration.ofMinutes(5);
                case "CHALLENGE" -> Duration.ofMinutes(30);
                default -> Duration.ofHours(1);  // ALLOW
            };

            // 1. Primary: security:hcad:analysis:{userId} (Hash - 전체 필드)
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Map<String, Object> fields = new HashMap<>();
            fields.put("action", action);
            fields.put("riskScore", analysisResult.getFinalScore());
            fields.put("confidence", analysisResult.getConfidence());
            fields.put("threatEvidence", String.join(", ", analysisResult.getIndicators()));
            fields.put("analysisDepth", analysisResult.getAnalysisDepth());
            fields.put("updatedAt", java.time.Instant.now().toString());

            redisTemplate.opsForHash().putAll(analysisKey, fields);
            if (ttl != null) {
                redisTemplate.expire(analysisKey, ttl);
            }

            log.info("[ColdPath][AI Native] Analysis saved to Redis: userId={}, action={}, riskScore={}, confidence={}, ttl={}",
                    userId, action,
                    String.format("%.3f", analysisResult.getFinalScore()),
                    String.format("%.3f", analysisResult.getConfidence()),
                    ttl != null ? ttl.toMinutes() + "m" : "permanent");

            // AI Native v3.4.0: BLOCK 판정 시 관리자 검토 대기열에 추가
            if ("BLOCK".equalsIgnoreCase(action) && adminOverrideService != null) {
                String requestId = (String) fields.get("requestId");
                if (requestId == null) {
                    requestId = UUID.randomUUID().toString();
                }
                String reasoning = String.join(", ", analysisResult.getIndicators());

                adminOverrideService.addToPendingReview(
                    requestId,
                    userId,
                    analysisResult.getFinalScore(),
                    analysisResult.getConfidence(),
                    reasoning
                );

                log.info("[ColdPath][AI Native] BLOCK 요청을 관리자 검토 대기열에 추가: userId={}, requestId={}",
                    userId, requestId);
            }

        } catch (Exception e) {
            log.error("[ColdPath] Failed to save analysis to Redis: userId={}", userId, e);
        }
    }

    /**
     * AI Native: Baseline Learning 수행
     *
     * LLM이 ALLOW + confidence >= 0.7 판정한 정상 요청을 학습하여
     * 다음 요청 분석 시 비교 기준선 제공
     *
     * 학습 조건 (BaselineLearningService 내부에서 검증):
     * - action = ALLOW
     * - confidence >= 0.7
     *
     * 학습 데이터:
     * - IP 대역 (C 클래스)
     * - 접근 시간대 (hour)
     * - 접근 경로
     *
     * @param userId 사용자 ID
     * @param event SecurityEvent (IP, 시간, 경로 추출)
     * @param analysisResult LLM 분석 결과 (action, confidence 포함)
     */
    private void learnFromAnalysisResult(String userId, SecurityEvent event, ThreatAnalysisResult analysisResult) {
        if (baselineLearningService == null) {
            log.debug("[ColdPath] BaselineLearningService not available, skipping baseline learning");
            return;
        }

        if (userId == null || userId.isBlank() || analysisResult == null) {
            return;
        }

        try {
            // ThreatAnalysisResult에서 SecurityDecision 추출
            SecurityDecision decision = analysisResult.getFinalDecision();

            // BaselineLearningService에 학습 요청
            // 내부에서 action=ALLOW, confidence>=0.7 조건 검증
            boolean learned = baselineLearningService.learnIfNormal(userId, decision, event);

            if (learned) {
                log.debug("[ColdPath][AI Native] Baseline learning completed: userId={}, action={}, confidence={}",
                    userId, decision.getAction(), String.format("%.3f", decision.getConfidence()));
            }

        } catch (Exception e) {
            log.warn("[ColdPath] Baseline learning failed (non-critical): userId={}", userId, e);
            // Baseline 학습 실패는 치명적이지 않음 - 다음 요청에서 재시도 가능
        }
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
     *
     * AI Native v4.2.0: Dead Code 제거
     * - assessments 필드 제거 (추가 코드 없음)
     * - getStrategiesUsed() 제거 (항상 빈 리스트)
     * - addIndicator(), addRecommendedAction() 제거 (호출처 없음)
     */
    @Getter @Setter
    public static class ThreatAnalysisResult {
        private double baseScore;
        private double finalScore;
        private double confidence;
        private Set<String> indicators = new HashSet<>();
        private Set<String> recommendedActions = new HashSet<>();
        private int analysisDepth = 0;
        // AI Native v3.3.0: LLM이 직접 결정한 action (4개 action 체계)
        // ALLOW, BLOCK, CHALLENGE, ESCALATE
        private String action;

        public List<String> getIndicators() { return new ArrayList<>(indicators); }

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
                .reasoning(reasoningPrefix)
                .build();
        }
    }
}