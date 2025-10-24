package io.contexa.contexacore.autonomous.tiered.feedback;

import io.contexa.contexacore.autonomous.config.FeedbackConstants;
import io.contexa.contexacore.autonomous.config.FeedbackIntegrationProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Layer 피드백 인덱싱 중앙화 서비스
 *
 * HCADVectorIntegrationService의 Layer1/2/3 피드백 인덱싱 로직을
 * 중앙화하여 UnifiedVectorService를 사용하도록 표준화합니다.
 *
 * 책임:
 * - Layer1 Fast Filter 피드백 인덱싱
 * - Layer2 Contextual Analysis 피드백 인덱싱
 * - Layer3 Expert Analysis 피드백 인덱싱
 * - 사용자별 피드백 집계 및 조회
 * - BaselineVector에 피드백 적용
 *
 * 개선 사항:
 * - StandardVectorStoreService → UnifiedVectorService 마이그레이션
 * - 캐싱 및 라우팅 자동화
 * - 일관된 인터페이스 및 오류 처리
 *
 * @since 3.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LayerFeedbackService {

    @Autowired(required = false)
    private final UnifiedVectorService unifiedVectorService;

    private final RedisTemplate<String, Object> redisTemplate;
    private final FeedbackIntegrationProperties feedbackProperties;

    /**
     * Layer1 피드백 인덱싱 (초고속 필터링 결과)
     *
     * @param event 보안 이벤트
     * @param decision 보안 결정
     */
    public void indexLayer1Feedback(SecurityEvent event, SecurityDecision decision) {
        try {
            String userId = event.getUserId() != null ? event.getUserId() : FeedbackConstants.DEFAULT_USER_ID;

            // Redis 저장
            String redisKey = feedbackProperties.getRedis().getLayer1FeedbackKeyPrefix() + userId;
            Map<String, Object> feedbackData = buildFeedbackData(event, decision, userId, "Layer1");

            redisTemplate.opsForList().rightPush(redisKey, feedbackData);
            redisTemplate.expire(redisKey, Duration.ofHours(1));

            // Vector Store 저장 (riskScore >= indexingThreshold)
            double indexingThreshold = feedbackProperties.getRiskScore().getIndexingThreshold();
            if (decision.getRiskScore() >= indexingThreshold) {
                indexToVectorStore(event, decision, userId, "Layer1");
            }

            log.info("Layer1 피드백 인덱싱 완료: userId={}, riskScore={}, threatCategory={}",
                userId, decision.getRiskScore(), decision.getThreatCategory());

        } catch (Exception e) {
            log.error("Layer1 피드백 인덱싱 실패", e);
        }
    }

    /**
     * Layer2 피드백 인덱싱 (컨텍스트 분석 결과)
     *
     * @param event 보안 이벤트
     * @param decision 보안 결정
     */
    public void indexLayer2Feedback(SecurityEvent event, SecurityDecision decision) {
        try {
            String userId = event.getUserId() != null ? event.getUserId() : FeedbackConstants.DEFAULT_USER_ID;

            // Redis 저장
            String redisKey = feedbackProperties.getRedis().getLayer2FeedbackKeyPrefix() + userId;
            Map<String, Object> feedbackData = buildFeedbackData(event, decision, userId, "Layer2");

            // Layer2는 세션 컨텍스트 정보 추가
            if (event.getSessionId() != null) {
                feedbackData.put("sessionId", event.getSessionId());
            }

            redisTemplate.opsForList().rightPush(redisKey, feedbackData);
            redisTemplate.expire(redisKey, Duration.ofHours(1));

            // Vector Store 저장 (riskScore >= indexingThreshold)
            double indexingThreshold = feedbackProperties.getRiskScore().getIndexingThreshold();
            if (decision.getRiskScore() >= indexingThreshold) {
                indexToVectorStore(event, decision, userId, "Layer2");
            }

            log.info("Layer2 피드백 인덱싱 완료: userId={}, riskScore={}, threatCategory={}",
                userId, decision.getRiskScore(), decision.getThreatCategory());

        } catch (Exception e) {
            log.error("Layer2 피드백 인덱싱 실패", e);
        }
    }

    /**
     * Layer3 피드백 인덱싱 (전문가 분석 결과)
     *
     * @param event 보안 이벤트
     * @param decision Layer3 분석 결과
     */
    @Retryable(
        value = {Exception.class},
        maxAttempts = 3,
        backoff = @Backoff(delay = 1000, multiplier = 2)
    )
    public void indexLayer3Feedback(SecurityEvent event, SecurityDecision decision) {
        try {
            String userId = event.getUserId() != null ? event.getUserId() : FeedbackConstants.DEFAULT_USER_ID;

            // Layer3는 Redis가 아닌 Vector Store에만 저장 (전문가 분석 결과는 장기 보관)
            String contextText = String.format(
                "Layer3 Expert Analysis - User: %s, EventType: %s, RiskScore: %.2f, " +
                "ThreatCategory: %s, Action: %s, MITRE: %s, Confidence: %.2f",
                userId,
                event.getEventType(),
                decision.getRiskScore(),
                decision.getThreatCategory(),
                decision.getAction(),
                decision.getMitreMapping() != null ? decision.getMitreMapping().keySet() : "[]",
                decision.getConfidence()
            );

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("documentType", VectorDocumentType.BEHAVIOR_ANALYSIS.getValue());
            metadata.put("source", FeedbackConstants.FEEDBACK_SOURCE);
            metadata.put("userId", userId);
            metadata.put("eventType", event.getEventType() != null ? event.getEventType().toString() : FeedbackConstants.DEFAULT_EVENT_TYPE);
            metadata.put("riskScore", decision.getRiskScore());
            metadata.put("threatCategory", decision.getThreatCategory());
            metadata.put("confidence", decision.getConfidence());
            metadata.put("timestamp", System.currentTimeMillis());

            Document doc = new Document(contextText, metadata);

            // UnifiedVectorService 사용
            if (unifiedVectorService != null) {
                unifiedVectorService.storeDocument(doc);
            } else {
                log.warn("UnifiedVectorService not available, Layer3 피드백 저장 실패");
            }

            log.info("Layer3 피드백 인덱싱 완료: userId={}, riskScore={}, threatCategory={}",
                userId, decision.getRiskScore(), decision.getThreatCategory());

        } catch (Exception e) {
            log.error("Layer3 피드백 인덱싱 실패", e);
        }
    }

    /**
     * 사용자별 Layer1 피드백 집계
     *
     * @param userId 사용자 ID
     * @return 집계된 Layer1 피드백 데이터
     */
    public Map<String, Object> getLayer1FeedbackForUser(String userId) {
        return getFeedbackForUser(userId, feedbackProperties.getRedis().getLayer1FeedbackKeyPrefix());
    }

    /**
     * 사용자별 Layer2 피드백 집계
     *
     * @param userId 사용자 ID
     * @return 집계된 Layer2 피드백 데이터
     */
    public Map<String, Object> getLayer2FeedbackForUser(String userId) {
        return getFeedbackForUser(userId, feedbackProperties.getRedis().getLayer2FeedbackKeyPrefix());
    }

    /**
     * 사용자별 Layer3 피드백 집계
     *
     * @param userId 사용자 ID
     * @return 집계된 Layer3 피드백 데이터
     */
    public Map<String, Object> getLayer3FeedbackForUser(String userId) {
        try {
            Map<String, Object> aggregated = new HashMap<>();
            List<String> threatCategories = new ArrayList<>();
            List<String> mitreTactics = new ArrayList<>();
            double totalRiskScore = 0.0;
            int feedbackCount = 0;

            Set<String> patternKeys = redisTemplate.keys(feedbackProperties.getRedis().getPatternKeyPrefix() + "*");
            if (patternKeys != null) {
                for (String patternKey : patternKeys) {
                    try {
                        int maxPatterns = feedbackProperties.getPattern().getMaxRecentPatterns();
                        List<Object> patterns = redisTemplate.opsForList().range(patternKey, -maxPatterns, -1);
                        if (patterns != null) {
                            for (Object pattern : patterns) {
                                try {
                                    Map<String, Object> feedback = (Map<String, Object>) pattern;

                                    String feedbackUserId = (String) feedback.get("userId");
                                    if (userId.equals(feedbackUserId)) {
                                        Double riskScore = (Double) feedback.get("riskScore");
                                        double indexingThreshold = feedbackProperties.getRiskScore().getIndexingThreshold();
                                        if (riskScore != null && riskScore >= indexingThreshold) {
                                            feedbackCount++;
                                            totalRiskScore += riskScore;

                                            String threatCategory = (String) feedback.get("threatCategory");
                                            if (threatCategory != null) {
                                                threatCategories.add(threatCategory);
                                            }

                                            // mitreTactics 역직렬화 오류 처리
                                            Object tacticsObj = feedback.get("mitreTactics");
                                            if (tacticsObj instanceof Collection) {
                                                try {
                                                    Collection<String> tactics = (Collection<String>) tacticsObj;
                                                    mitreTactics.addAll(tactics);
                                                } catch (Exception e) {
                                                    log.warn("mitreTactics 역직렬화 실패 (잘못된 데이터 무시): {}", e.getMessage());
                                                }
                                            }
                                        }
                                    }
                                } catch (Exception e) {
                                    log.warn("개별 피드백 처리 실패 (무시하고 계속): {}", e.getMessage());
                                }
                            }
                        }
                    } catch (Exception e) {
                        log.warn("패턴 키 {} 처리 실패 (무시하고 계속): {}", patternKey, e.getMessage());
                    }
                }
            }

            aggregated.put("feedbackCount", feedbackCount);
            aggregated.put("averageRiskScore", feedbackCount > 0 ? totalRiskScore / feedbackCount : 0.0);
            aggregated.put("threatCategories", threatCategories.stream().distinct().collect(Collectors.toList()));
            aggregated.put("mitreTactics", mitreTactics.stream().distinct().collect(Collectors.toList()));
            double highRiskThreshold = feedbackProperties.getRiskScore().getHighRiskThreshold();
            aggregated.put("hasHighRiskHistory", totalRiskScore / Math.max(1, feedbackCount) >= highRiskThreshold);

            log.debug("Layer3 피드백 집계: userId={}, count={}, avgRisk={}",
                userId, feedbackCount, aggregated.get("averageRiskScore"));

            return aggregated;

        } catch (Exception e) {
            log.error("Layer3 피드백 조회 실패: userId={}", userId, e);
            return Map.of("feedbackCount", 0, "averageRiskScore", 0.0);
        }
    }

    // === Private Helper Methods ===

    /**
     * 피드백 데이터 생성
     */
    private Map<String, Object> buildFeedbackData(SecurityEvent event, SecurityDecision decision, String userId, String source) {
        Map<String, Object> feedbackData = new HashMap<>();
        feedbackData.put("userId", userId);
        feedbackData.put("riskScore", decision.getRiskScore());
        feedbackData.put("confidence", decision.getConfidence());
        feedbackData.put("threatCategory", decision.getThreatCategory());
        feedbackData.put("action", decision.getAction() != null ? decision.getAction().toString() : "UNKNOWN");
        feedbackData.put("timestamp", System.currentTimeMillis());
        feedbackData.put("eventType", event.getEventType() != null ? event.getEventType().toString() : FeedbackConstants.DEFAULT_EVENT_TYPE);
        feedbackData.put("source", source);
        return feedbackData;
    }

    /**
     * Vector Store에 인덱싱
     */
    private void indexToVectorStore(SecurityEvent event, SecurityDecision decision, String userId, String source) {
        try {
            String contextText = String.format(
                "%s - User: %s, EventType: %s, RiskScore: %.2f, ThreatCategory: %s, Action: %s, Confidence: %.2f",
                source, userId, event.getEventType(), decision.getRiskScore(),
                decision.getThreatCategory(), decision.getAction(), decision.getConfidence()
            );

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("documentType", VectorDocumentType.BEHAVIOR_ANALYSIS.getValue());
            metadata.put("source", source);
            metadata.put("userId", userId);
            metadata.put("eventType", event.getEventType() != null ? event.getEventType().toString() : FeedbackConstants.DEFAULT_EVENT_TYPE);
            metadata.put("riskScore", decision.getRiskScore());
            metadata.put("threatCategory", decision.getThreatCategory());
            metadata.put("confidence", decision.getConfidence());
            metadata.put("timestamp", System.currentTimeMillis());

            Document doc = new Document(contextText, metadata);

            // UnifiedVectorService 사용
            if (unifiedVectorService != null) {
                unifiedVectorService.storeDocument(doc);
            } else {
                log.warn("UnifiedVectorService not available, {} 피드백 Vector Store 저장 실패", source);
            }

        } catch (Exception e) {
            log.error("{} Vector Store 인덱싱 실패", source, e);
        }
    }

    /**
     * Layer별 피드백 집계 공통 로직
     */
    private Map<String, Object> getFeedbackForUser(String userId, String redisKeyPrefix) {
        try {
            String redisKey = redisKeyPrefix + userId;
            int maxPatterns = feedbackProperties.getPattern().getMaxRecentPatterns();
            List<Object> feedbackList = redisTemplate.opsForList().range(redisKey, -maxPatterns, -1);

            if (feedbackList == null || feedbackList.isEmpty()) {
                return Map.of("feedbackCount", 0, "averageRiskScore", 0.0);
            }

            double totalRiskScore = 0.0;
            int feedbackCount = 0;
            List<String> threatCategories = new ArrayList<>();

            for (Object item : feedbackList) {
                Map<String, Object> feedback = (Map<String, Object>) item;
                Double riskScore = (Double) feedback.get("riskScore");
                if (riskScore != null) {
                    totalRiskScore += riskScore;
                    feedbackCount++;

                    String threatCategory = (String) feedback.get("threatCategory");
                    if (threatCategory != null) {
                        threatCategories.add(threatCategory);
                    }
                }
            }

            Map<String, Object> aggregated = new HashMap<>();
            aggregated.put("feedbackCount", feedbackCount);
            aggregated.put("averageRiskScore", feedbackCount > 0 ? totalRiskScore / feedbackCount : 0.0);
            aggregated.put("threatCategories", threatCategories.stream().distinct().collect(Collectors.toList()));
            double highRiskThreshold = feedbackProperties.getRiskScore().getHighRiskThreshold();
            aggregated.put("hasHighRiskHistory", totalRiskScore / Math.max(1, feedbackCount) >= highRiskThreshold);

            log.debug("{} 피드백 집계: userId={}, count={}, avgRisk={}",
                redisKeyPrefix, userId, feedbackCount, aggregated.get("averageRiskScore"));

            return aggregated;

        } catch (Exception e) {
            log.error("{} 피드백 조회 실패: userId={}", redisKeyPrefix, userId, e);
            return Map.of("feedbackCount", 0, "averageRiskScore", 0.0);
        }
    }
}
