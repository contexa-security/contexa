package io.contexa.contexacore.autonomous.security.processor;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Hot Path 이벤트 처리기
 * 
 * 낮은 위협 점수(< 0.7)의 이벤트를 AI 진단 없이 빠르게 처리합니다.
 * 목표: 50ms 이내 처리 완료
 * 
 * 주요 기능:
 * - Trust Score 즉시 업데이트
 * - 기본 위협 점수 기록
 * - 정상 패턴 학습
 * - 최소한의 메타데이터 저장
 * 
 * @author contexa Platform
 * @since 1.0
 */
@Slf4j
public class HotPathEventProcessor implements IPathProcessor {

    private final RedisTemplate<String, Object> redisTemplate;
    private final VectorStore vectorStore;

    // 처리 통계
    private final AtomicLong processedCount = new AtomicLong(0);
    private final AtomicLong totalProcessingTime = new AtomicLong(0);
    private volatile long lastProcessedTimestamp = 0;

    // 설정값
    @Value("${security.hotpath.ttl.hours:24}")
    private int ttlHours;

    @Value("${security.hotpath.trust.increment:0.01}")
    private double trustScoreIncrement;

    @Value("${security.hotpath.pattern.learning:true}")
    private boolean enablePatternLearning;

    @Value("${security.hotpath.vector.storage:true}")
    private boolean enableVectorStorage;

    @Value("${security.hotpath.zerotrust.enabled:true}")
    private boolean enableZeroTrustVerification;

    @Value("${security.hotpath.zerotrust.threshold:0.70}")
    private double zeroTrustThreshold;

    @Autowired
    public HotPathEventProcessor(RedisTemplate<String, Object> redisTemplate,
                                 @Autowired(required = false) VectorStore vectorStore) {
        this.redisTemplate = redisTemplate;
        this.vectorStore = vectorStore;
    }
    
    @Override
    public ProcessingResult processEvent(SecurityEvent event, double riskScore) {
        long startTime = System.currentTimeMillis();
        
        try {
            String userId = event.getUserId();
            if (userId == null) {
                log.warn("Hot Path: userId가 없는 이벤트 - eventId: {}", event.getEventId());
                return ProcessingResult.failure(
                    ProcessingResult.ProcessingPath.HOT_PATH,
                    "Missing userId"
                );
            }
            
            log.debug("Hot Path 처리 시작 - userId: {}, riskScore: {}", userId, riskScore);
            
            // ProcessingResult 생성
            ProcessingResult result = ProcessingResult.builder()
                    .processingPath(ProcessingResult.ProcessingPath.HOT_PATH)
                    .currentRiskLevel(riskScore)
                    .build();
            
            // 1. 현재 threat_score 읽기 (읽기만!)
            Double currentThreatScore = readCurrentThreatScore(userId);
            
            // 2. 위협 점수 조정값 계산 (업데이트하지 않음)
            double adjustment = calculateThreatAdjustment(riskScore, currentThreatScore);
            result.setThreatScoreAdjustment(adjustment);
            
            // 3. 정상 패턴 학습 (비동기 처리 권장)
            if (enablePatternLearning && riskScore < 0.3) {
                CompletableFuture.runAsync(() -> learnNormalPattern(userId, event));
                result.addAnalysisData("patternLearning", true);
            }

            // 4. 벡터 데이터베이스에 저장 (98% 정상 패턴 학습)
            if (enableVectorStorage && riskScore < 0.7) {
                CompletableFuture.runAsync(() -> storeInVectorDatabase(event, riskScore));
                result.addAnalysisData("vectorStorage", true);
            }

            // 5. 분석 데이터 추가
            result.addAnalysisData("eventType", event.getEventType().toString());
            result.addAnalysisData("sourceIp", event.getSourceIp());
            result.addAnalysisData("riskScore", riskScore);
            
            // 통계 업데이트
            long processingTime = System.currentTimeMillis() - startTime;
            processedCount.incrementAndGet();
            totalProcessingTime.addAndGet(processingTime);
            lastProcessedTimestamp = System.currentTimeMillis();
            
            // 결과에 처리 시간 설정
            result.setProcessingTimeMs(processingTime);
            result.setProcessedAt(LocalDateTime.now());
            result.setStatus(ProcessingResult.ProcessingStatus.SUCCESS);
            
            if (processingTime > 50) {
                log.warn("Hot Path 처리 시간 초과 - {}ms (목표: 50ms)", processingTime);
                result.addAnalysisData("performanceWarning", "Exceeded 50ms target");
            } else {
                log.debug("Hot Path 처리 완료 - userId: {}, 시간: {}ms", userId, processingTime);
            }
            
            return result;
            
        } catch (Exception e) {
            log.error("Hot Path 처리 실패 - eventId: {}", event.getEventId(), e);
            // Hot Path는 실패해도 시스템이 멈추면 안 됨
            return ProcessingResult.failure(
                ProcessingResult.ProcessingPath.HOT_PATH,
                "Processing failed: " + e.getMessage()
            );
        }
    }
    
    /**
     * 현재 threat_score 읽기 (읽기만!)
     * 프로젝트 센티넬에 따라 업데이트는 SecurityPlaneAgent가 수행
     */
    private Double readCurrentThreatScore(String userId) {
        try {
            String threatScoreKey = ZeroTrustRedisKeys.threatScore(userId);
            Object score = redisTemplate.opsForValue().get(threatScoreKey);
            
            if (score != null) {
                if (score instanceof Number) {
                    return ((Number) score).doubleValue();
                }
            }
            
            log.trace("현재 threat_score - userId: {}, score: {}", userId, score);
            return 0.5; // 기본값
            
        } catch (Exception e) {
            log.error("threat_score 읽기 실패 - userId: {}", userId, e);
            return 0.5;
        }
    }
    
    /**
     * Threat Score 조정값 계산
     *
     * 설계 원칙:
     * - Trust Score = 1.0 - Threat Score
     * - adjustment > 0: Threat 증가 (Trust 감소)
     * - adjustment < 0: Threat 감소 (Trust 증가)
     *
     * 개선된 계산 방식:
     * - 낮은 위험 (< 0.3): 위험도에 반비례하여 Trust 증가
     *   예) riskScore 0.0 → -0.03, 0.1 → -0.02, 0.29 → -0.001
     * - 높은 위험 (>= 0.7): 위험도에 비례하여 Threat 증가
     * - 중간 위험 (0.3~0.7): 조정 없음 (관찰 유지)
     *
     * @param riskScore 현재 이벤트의 위험도 (0.0~1.0)
     * @param currentThreatScore 현재 Threat Score (0.0~1.0)
     * @return Threat Score 조정값
     */
    private double calculateThreatAdjustment(double riskScore, Double currentThreatScore) {
        // 낮은 위험 (< 0.3): 위험도에 반비례한 Trust 증가
        if (riskScore < 0.3) {
            // 위험도가 낮을수록 더 큰 Trust 증가
            // 0.0 → -0.03, 0.1 → -0.02, 0.2 → -0.01, 0.29 → -0.001
            return -(0.3 - riskScore) * 0.1;
        }

        // 높은 위험 (>= 0.7): Threat 증가 (Trust 감소)
        else if (riskScore >= 0.7) {
            // 위험도에 비례한 증가 (0.7~1.0 → 0.07~0.1)
            return riskScore * 0.1;
        }

        // 중간 위험 (0.3~0.7): 조정 없음 (관찰 유지)
        return 0.0;
    }
    
    /**
     * 정상 패턴 학습 (낮은 위험일 때만)
     */
    private void learnNormalPattern(String userId, SecurityEvent event) {
        try {
            String patternKey = ZeroTrustRedisKeys.normalPattern(userId);

            Map<String, Object> pattern = new HashMap<>();
            pattern.put("lastNormalActivity", LocalDateTime.now().toString());
            pattern.put("eventType", event.getEventType().toString());
            pattern.put("sourceIp", event.getSourceIp());

            // Hash로 저장 (빠른 업데이트)
            redisTemplate.opsForHash().putAll(patternKey, pattern);
            redisTemplate.expire(patternKey, Duration.ofDays(7));

        } catch (Exception e) {
            // 패턴 학습 실패는 무시 (선택적 기능)
            log.trace("패턴 학습 실패 - userId: {}", userId, e);
        }
    }

    /**
     * 벡터 데이터베이스에 정상 패턴 저장
     *
     * ⭐ CRITICAL: 98% Low-Risk 이벤트의 정상 행동 패턴 학습
     *
     * 저장되는 데이터:
     * - documentType: "behavior" (필수, BehaviorVectorService 필터용)
     * - userId: 사용자 ID (필수, 유사도 검색용)
     * - eventId: 이벤트 고유 ID
     * - timestamp: ISO 8601 DateTime String (Layer2/3 검색용)
     * - riskScore: 위험도 (정상 패턴 식별용)
     * - threatActor: "NONE" (정상 패턴 표시)
     * - assetCriticality: "LOW" (정상 활동)
     *
     * @param event SecurityEvent
     * @param riskScore 위험도 (< 0.7)
     */
    private void storeInVectorDatabase(SecurityEvent event, double riskScore) {
        if (vectorStore == null) {
            log.trace("VectorStore not available, skipping normal pattern storage");
            return;
        }

        try {
            // NULL 검증 및 기본값 처리
            String userId = event.getUserId();
            if (userId == null || userId.isEmpty() || "unknown".equals(userId)) {
                log.warn("Invalid userId for vector storage: eventId={}", event.getEventId());
                return; // userId 없으면 저장 안 함 (BehaviorVectorService 필터 실패)
            }

            String eventId = event.getEventId();
            if (eventId == null || eventId.isEmpty()) {
                log.warn("Invalid eventId for vector storage: userId={}", userId);
                return;
            }

            String sourceIp = event.getSourceIp();
            if (sourceIp == null || sourceIp.isEmpty()) {
                sourceIp = "UNKNOWN_IP"; // 기본값 설정
            }

            String eventType = event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN_TYPE";

            // 정상 패턴 문서 생성
            String content = String.format(
                    "Normal Activity: user=%s, event=%s, ip=%s, risk=%.3f, pattern=low-risk-hotpath",
                    userId, eventType, sourceIp, riskScore
            );

            Map<String, Object> metadata = new HashMap<>();

            // ⭐ 필수 공통 metadata
            metadata.put("documentType", "behavior");
            metadata.put("eventId", eventId);
            metadata.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            metadata.put("userId", userId);

            // SecurityEvent 정보
            metadata.put("eventType", eventType);
            metadata.put("sourceIp", sourceIp);
            metadata.put("sessionId", event.getSessionId() != null ? event.getSessionId() : "");

            // 위험도 정보 (정상 패턴)
            metadata.put("riskScore", riskScore);
            metadata.put("threatCategory", "NORMAL");

            // Layer3 ThreatIntelligence용 (정상 패턴)
            metadata.put("threatActor", "NONE");
            metadata.put("campaignId", "NONE");
            metadata.put("campaignName", "");
            metadata.put("incidentId", "");
            metadata.put("mitreTactic", "");
            metadata.put("assetCriticality", "LOW");
            metadata.put("iocIndicator", "");

            // HotPath 전용 메타데이터
            metadata.put("processingPath", "HOT_PATH");
            metadata.put("patternType", "normal");
            metadata.put("learningSource", "hotpath-processor");

            Document document = new Document(content, metadata);
            vectorStore.add(List.of(document));

            log.debug("Stored normal pattern in VectorStore: userId={}, eventId={}, riskScore={}",
                    userId, eventId, riskScore);

        } catch (Exception e) {
            // 벡터 저장 실패는 시스템 중단 없이 로그만 기록
            log.debug("Failed to store normal pattern in VectorStore: eventId={}", event.getEventId(), e);
        }
    }


    @Override
    public ProcessingMode getProcessingMode() {
        return ProcessingMode.PASS_THROUGH;
    }
    
    @Override
    public String getProcessorName() {
        return "HotPathEventProcessor";
    }
    
    @Override
    public boolean isReady() {
        // Redis 연결 확인
        try {
            redisTemplate.getConnectionFactory().getConnection().ping();
            return true;
        } catch (Exception e) {
            log.error("Redis 연결 실패", e);
            return false;
        }
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
}