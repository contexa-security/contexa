package io.contexa.contexacore.hcad.service;

import io.contexa.contexacore.autonomous.config.FeedbackIntegrationProperties;
import io.contexa.contexacore.autonomous.tiered.feedback.LayerFeedbackService;
import io.contexa.contexacore.hcad.domain.BaselineVector;
import io.contexa.contexacore.hcad.domain.HCADContext;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * HCAD와 PGVector 통합 서비스
 *
 * BehaviorVectorService의 고차원 임베딩을 HCAD의 실시간 이상 탐지에 활용
 * Cold Path의 학습 결과를 Hot Path에서 즉시 사용 가능하도록 연동
 *
 * @since 2.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class HCADVectorIntegrationService {

    private final BehaviorVectorService behaviorVectorService;
    private final UnifiedVectorService unifiedVectorService;
    private final RedisTemplate<String, Object> redisTemplate;
    private final FeedbackIntegrationProperties feedbackProperties;
    private final LayerFeedbackService layerFeedbackService;
    private final EmbeddingService embeddingService; // EmbeddingService 주입

    @Autowired(required = false)
    private EmbeddingModel embeddingModel;

    @Value("${hcad.vector.embedding-dimension:384}")
    private int embeddingDimension;

    @Value("${hcad.vector.cache-ttl-hours:24}")
    private long cacheTtlHours;

    @Value("${hcad.vector.similarity-threshold:0.85}")
    private double similarityThreshold;

    @Value("${hcad.vector.max-cached-embeddings:1000}")
    private int maxCachedEmbeddings;

    @Value("${hcad.vector.scenario-detection-enabled:true}")
    private boolean scenarioDetectionEnabled;

    /**
     * HCADContext를 고차원 임베딩으로 변환
     * EmbeddingService로 위임
     *
     * @param context HCAD 컨텍스트
     * @return 384차원 임베딩 벡터
     */
    public float[] generateContextEmbedding(HCADContext context) {
        return embeddingService.generateContextEmbedding(context);
    }

    /**
     * BehaviorVectorService의 학습된 패턴을 HCAD BaselineVector에 통합
     *
     * @param userId 사용자 ID
     * @param baseline 기존 HCAD 기준선
     * @return 업데이트된 기준선
     */
    public BaselineVector integrateLearnedPatterns(String userId, BaselineVector baseline) {
        try {
            // BehaviorVectorService에서 유사 행동 패턴 검색
            List<Document> similarBehaviors = behaviorVectorService.findSimilarBehaviors(
                userId,
                "normal_activity",
                10
            );

            if (!similarBehaviors.isEmpty()) {
                // 패턴들을 평균하여 고차원 임베딩 생성 (EmbeddingService 위임)
                float[] averageEmbedding = embeddingService.calculateAverageEmbedding(similarBehaviors);

                // BaselineVector에 고차원 임베딩 설정
                baseline.setHighDimensionalEmbedding(averageEmbedding);
                baseline.setEmbeddingVersion("BehaviorVectorService-v2.0");
                baseline.setEmbeddingUpdatedAt(Instant.now());

                // 시나리오 패턴 업데이트
                if (scenarioDetectionEnabled) {
                    updateScenarioPatterns(baseline, similarBehaviors);
                }

                log.debug("사용자 {} 패턴 통합 완료: {} 개 행동 패턴 적용", userId, similarBehaviors.size());
            }

        } catch (Exception e) {
            log.error("패턴 통합 실패: {}", e.getMessage());
        }

        return baseline;
    }

    /**
     * 실시간 행동 이상 탐지를 위한 빠른 임베딩 비교
     *
     * Behavioral Anomaly Score: 사용자의 현재 행동이 과거 정상 패턴과 얼마나 다른지 측정
     * - 0.0: 정상 패턴과 완전히 일치 (이상 없음)
     * - 0.5: 중간 정도의 행동 변화 (주의 필요)
     * - 1.0: 정상 패턴과 완전히 다름 (심각한 이상)
     *
     * 용도: HCAD 필터에서 실시간 이상 탐지 (5-30ms 처리 시간)
     * 범위: Hot Path (빠른 필터링) 전용
     *
     * @param contextEmbedding 현재 컨텍스트 임베딩 (384-dim)
     * @param userId 사용자 ID
     * @return Behavioral Anomaly Score (0.0 ~ 1.0)
     */
    public double calculateRealTimeAnomalyScore(float[] contextEmbedding, String userId) {
        try {
            // Redis 에서 캐싱된 사용자 정상 패턴 임베딩 조회 (EmbeddingService 위임)
            float[] normalEmbedding = embeddingService.getCachedNormalEmbedding(userId);

            if (normalEmbedding == null) {
                // 캐시 미스 시 PGVector 에서 조회
                normalEmbedding = fetchNormalEmbeddingFromPGVector(userId);
            }

            if (normalEmbedding != null) {
                // 코사인 유사도 계산 (EmbeddingService 위임)
                double similarity = embeddingService.calculateCosineSimilarity(contextEmbedding, normalEmbedding);

                // 이상 점수 = 1 - 유사도
                double anomalyScore = 1.0 - similarity;

                // 임계값 기반 조정
                if (similarity < similarityThreshold) {
                    // 유사도가 임계값보다 낮으면 이상 점수 증가
                    anomalyScore = Math.min(1.0, anomalyScore * 1.2);
                }

                return anomalyScore;
            }

        } catch (Exception e) {
            log.error("실시간 이상 점수 계산 실패: {}", e.getMessage());
        }

        return 0.5; // 중립값 반환
    }

    /**
     * 시나리오 자동 감지 및 분류
     *
     * @param context HCAD 컨텍스트
     * @return 감지된 시나리오 이름
     */
    public String detectScenario(HCADContext context) {
        // 시간대 기반 시나리오
        int hour = context.getTimestamp().atZone(java.time.ZoneId.systemDefault()).getHour();
        boolean isWeekend = context.getTimestamp().atZone(java.time.ZoneId.systemDefault())
            .getDayOfWeek().getValue() >= 6;

        // IP 기반 위치 추정
        boolean isInternalNetwork = isInternalIp(context.getRemoteIp());

        // 디바이스 타입 추정
        boolean isMobileDevice = context.getUserAgent() != null &&
            (context.getUserAgent().contains("Mobile") || context.getUserAgent().contains("Android"));

        // 시나리오 결정 로직
        if (isWeekend) {
            if (isInternalNetwork) {
                return "weekend_home";
            } else {
                return "weekend_external";
            }
        } else { // 평일
            if (hour >= 9 && hour < 18) {
                if (isInternalNetwork) {
                    return "weekday_office";
                } else if (isMobileDevice) {
                    return "weekday_mobile";
                } else {
                    return "weekday_remote";
                }
            } else if (hour >= 18 && hour < 22) {
                return "evening_activity";
            } else if (hour >= 22 || hour < 6) {
                return "night_activity";
            } else {
                return "early_morning";
            }
        }
    }

    /**
     * Cold Path 학습 결과를 Hot Path에 비동기 동기화
     *
     * Phase 1: 베이스라인 임베딩 업데이트
     * Phase 2: Cold Path AI 진단 결과 동기화 (NEW)
     */
    @Async
    public CompletableFuture<Void> syncColdPathToHotPath(String userId) {
        return CompletableFuture.runAsync(() -> {
            try {
                log.info("Cold Path → Hot Path 동기화 시작: userId={}", userId);

                // Phase 1: BehaviorVectorService 에서 최신 학습 패턴 조회
                List<Document> recentPatterns = behaviorVectorService.findSimilarBehaviors(
                    userId,
                    "recent_activity",
                    20
                );

                if (!recentPatterns.isEmpty()) {
                    // 패턴들을 분석하여 고차원 임베딩 생성 (EmbeddingService 위임)
                    float[] updatedEmbedding = embeddingService.calculateWeightedEmbedding(recentPatterns);

                    // Redis에 즉시 업데이트 (Hot Path 에서 사용)
                    String embeddingKey = "hcad:baseline:v2:" + userId;
                    redisTemplate.opsForValue().set(
                        embeddingKey,
                        updatedEmbedding,
                        Duration.ofHours(cacheTtlHours)
                    );

                    // 시나리오별 패턴도 업데이트
                    Map<String, float[]> scenarioEmbeddings = extractScenarioEmbeddings(recentPatterns);
                    for (Map.Entry<String, float[]> entry : scenarioEmbeddings.entrySet()) {
                        String scenarioKey = String.format("hcad:embedding:scenario:%s:%s",
                            userId, entry.getKey());
                        redisTemplate.opsForValue().set(
                            scenarioKey,
                            entry.getValue(),
                            Duration.ofHours(cacheTtlHours)
                        );
                    }

                    log.info("Phase 1 완료: userId={}, 패턴 수={}, 시나리오 수={}",
                        userId, recentPatterns.size(), scenarioEmbeddings.size());
                }

                // Phase 2: Cold Path AI 진단 결과 동기화 (NEW)
                syncColdPathAnalysisResult(userId);

            } catch (Exception e) {
                log.error("Cold Path → Hot Path 동기화 실패: userId={}", userId, e);
            }
        });
    }

    /**
     * Cold Path AI 진단 결과를 Hot Path에 동기화
     *
     * ColdPathEventProcessor가 Redis에 저장한 분석 결과를 읽어서
     * Hot Path(HCADFilter)가 사용할 수 있는 형태로 변환하여 저장
     */
    private void syncColdPathAnalysisResult(String userId) {
        try {
            // Cold Path 분석 결과 조회
            String analysisKey = "security:hcad:analysis:" + userId;
            Map<Object, Object> analysis = redisTemplate.opsForHash().entries(analysisKey);

            if (analysis == null || analysis.isEmpty()) {
                log.debug("Cold Path 분석 결과 없음: userId={}", userId);
                return;
            }

            // threatScoreAdjustment 추출 및 저장
            Object threatAdjustmentObj = analysis.get("threatScoreAdjustment");
            if (threatAdjustmentObj != null) {
                double threatAdjustment = Double.parseDouble(threatAdjustmentObj.toString());

                // Hot Path에서 사용할 Redis 키에 저장
                String threatKey = io.contexa.contexacore.hcad.constants.HCADRedisKeys.threatAdjustment(userId);
                redisTemplate.opsForValue().set(
                    threatKey,
                    threatAdjustment,
                    Duration.ofHours(1) // 1시간 TTL
                );

                log.info("Phase 2 완료: userId={}, threatAdjustment={}",
                    userId, String.format("%.3f", threatAdjustment));
            }

        } catch (Exception e) {
            log.warn("Cold Path 분석 결과 동기화 실패: userId={}", userId, e);
        }
    }

    /**
     * 임베딩 사전 계산 및 캐싱 (배치 작업)
     */
    @Async
    public CompletableFuture<Void> precomputeEmbeddings(List<String> userIds) {
        return CompletableFuture.runAsync(() -> {
            log.info("임베딩 사전 계산 시작: {} 명 사용자", userIds.size());

            int processed = 0;
            for (String userId : userIds) {
                try {
                    // 사용자별 정상 패턴 임베딩 계산
                    List<Document> userPatterns = behaviorVectorService.findSimilarBehaviors(
                        userId, "normal_pattern", 50
                    );

                    if (!userPatterns.isEmpty()) {
                        // 임베딩 계산 및 캐싱 (EmbeddingService 위임)
                        float[] embedding = embeddingService.calculateAverageEmbedding(userPatterns);
                        embeddingService.cacheNormalEmbedding(userId, embedding);
                        processed++;
                    }

                } catch (Exception e) {
                    log.error("사용자 {} 임베딩 사전 계산 실패", userId, e);
                }

                // 처리 진행 상황 로깅
                if (processed % 100 == 0) {
                    log.info("임베딩 사전 계산 진행: {}/{}", processed, userIds.size());
                }
            }

            log.info("임베딩 사전 계산 완료: {}/{} 처리됨", processed, userIds.size());
        });
    }

    // === Private Helper Methods ===
    // 중복 메소드 제거됨 - EmbeddingService로 위임

    private float[] fetchNormalEmbeddingFromPGVector(String userId) {
        try {
            // PGVector에서 사용자 정상 패턴 검색
            SearchRequest searchRequest = SearchRequest.builder()
                .query(String.format("userId:%s AND type:normal_pattern", userId))
                .topK(5)
                .similarityThreshold(0.9)
                .build();

            List<Document> normalPatterns = unifiedVectorService.searchSimilar(searchRequest);

            if (!normalPatterns.isEmpty()) {
                // EmbeddingService 위임
                float[] embedding = embeddingService.calculateAverageEmbedding(normalPatterns);
                // 캐싱
                embeddingService.cacheNormalEmbedding(userId, embedding);
                return embedding;
            }

        } catch (Exception e) {
            log.error("PGVector에서 정상 임베딩 조회 실패: {}", e.getMessage());
        }

        return null;
    }

    // calculateAverageEmbedding, calculateWeightedEmbedding, calculateCosineSimilarity
    // 모두 EmbeddingService로 위임됨 (중복 제거)

    private void updateScenarioPatterns(BaselineVector baseline, List<Document> behaviors) {
        Map<String, List<Document>> scenarioBehaviors = new HashMap<>();

        // 행동을 시나리오별로 그룹화
        for (Document behavior : behaviors) {
            String scenario = detectScenarioFromDocument(behavior);
            scenarioBehaviors.computeIfAbsent(scenario, k -> new ArrayList<>()).add(behavior);
        }

        // 각 시나리오별 패턴 업데이트
        for (Map.Entry<String, List<Document>> entry : scenarioBehaviors.entrySet()) {
            String scenario = entry.getKey();
            List<Document> docs = entry.getValue();

            // HCADContext 생성 (문서에서 추출)
            HCADContext avgContext = createAverageContext(docs);
            if (avgContext != null) {
                baseline.updateScenarioPattern(scenario, avgContext, 0.1);
            }
        }
    }

    /**
     * 시나리오별 임베딩 추출
     * EmbeddingService 위임
     */
    private Map<String, float[]> extractScenarioEmbeddings(List<Document> patterns) {
        Map<String, List<Document>> scenarioGroups = patterns.stream()
            .collect(Collectors.groupingBy(this::detectScenarioFromDocument));

        Map<String, float[]> scenarioEmbeddings = new HashMap<>();

        for (Map.Entry<String, List<Document>> entry : scenarioGroups.entrySet()) {
            String scenario = entry.getKey();
            List<Document> docs = entry.getValue();
            // EmbeddingService 사용
            float[] embedding = embeddingService.calculateAverageEmbedding(docs);
            scenarioEmbeddings.put(scenario, embedding);
        }

        return scenarioEmbeddings;
    }

    private String detectScenarioFromDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        // 메타데이터에서 시나리오 힌트 추출
        Object hourObj = metadata.get("hour");
        Object isWeekendObj = metadata.get("isWeekend");
        Object ipTypeObj = metadata.get("ipType");

        int hour = hourObj != null ? Integer.parseInt(hourObj.toString()) : 12;
        boolean isWeekend = Boolean.parseBoolean(String.valueOf(isWeekendObj));
        String ipType = ipTypeObj != null ? ipTypeObj.toString() : "EXTERNAL";

        // 시나리오 결정
        if (isWeekend) {
            return "weekend_" + ipType.toLowerCase();
        } else {
            if (hour >= 9 && hour < 18) {
                return "weekday_office";
            } else if (hour >= 18 && hour < 22) {
                return "evening_activity";
            } else {
                return "night_activity";
            }
        }
    }

    private HCADContext createAverageContext(List<Document> documents) {
        if (documents.isEmpty()) {
            return null;
        }

        // 문서들의 메타데이터를 평균하여 컨텍스트 생성
        HCADContext.HCADContextBuilder builder = HCADContext.builder();

        // 첫 번째 문서에서 기본 정보 추출
        Map<String, Object> firstMeta = documents.get(0).getMetadata();
        builder.userId((String) firstMeta.get("userId"));
        builder.sessionId(UUID.randomUUID().toString());

        // 평균값 계산
        double avgTrust = 0;
        int avgRequests = 0;

        for (Document doc : documents) {
            Map<String, Object> meta = doc.getMetadata();
            Object trustObj = meta.get("trustScore");
            Object reqObj = meta.get("requestCount");

            if (trustObj != null) {
                avgTrust += Double.parseDouble(trustObj.toString());
            }
            if (reqObj != null) {
                avgRequests += Integer.parseInt(reqObj.toString());
            }
        }

        builder.currentTrustScore(avgTrust / documents.size());
        builder.recentRequestCount(avgRequests / documents.size());
        builder.timestamp(Instant.now());

        return builder.build();
    }

    private boolean isInternalIp(String ip) {
        return ip != null && (
            ip.startsWith("10.") ||
            ip.startsWith("192.168.") ||
            ip.startsWith("172.16.") ||
            ip.startsWith("127.")
        );
    }

    /**
     * Phase 6.1: Layer3 피드백을 BaselineVector에 적용
     *
     * @param baseline 기준선 벡터
     * @param userId 사용자 ID
     */
    public void applyLayer3FeedbackToBaseline(BaselineVector baseline, String userId) {
        try {
            Map<String, Object> feedback = layerFeedbackService.getLayer3FeedbackForUser(userId);

            int feedbackCount = (int) feedback.get("feedbackCount");
            if (feedbackCount == 0) {
                return;
            }

            double avgRiskScore = (double) feedback.get("averageRiskScore");
            boolean hasHighRisk = (boolean) feedback.getOrDefault("hasHighRiskHistory", false);

            if (hasHighRisk) {
                double oldConfidence = baseline.getConfidence();
                double confidenceBoost = 1.1;
                baseline.setConfidence(Math.min(1.0, oldConfidence * confidenceBoost));

                List<String> threatCategories = (List<String>) feedback.get("threatCategories");
                if (threatCategories != null && !threatCategories.isEmpty()) {
                    double[] currentVector = baseline.getVector();
                    if (currentVector != null && currentVector.length > 0) {
                        for (int i = 0; i < currentVector.length; i++) {
                            currentVector[i] *= 0.95;
                        }
                        baseline.setVector(currentVector);
                    }
                }

                log.info("Layer3 고위험 피드백 적용: userId={}, 신뢰도 증가: {} → {}, 벡터 조정 완료, 위협 카테고리: {}",
                    userId, oldConfidence, baseline.getConfidence(),
                    threatCategories != null ? String.join(", ", threatCategories) : "none");
            }


        } catch (Exception e) {
            log.error("Layer3 피드백 적용 실패: userId={}", userId, e);
        }
    }

    /**
     * 모든 Layer의 피드백을 통합하여 BaselineVector에 적용
     * 가중치: Layer3 (70%) + Layer2 (20%) + Layer1 (10%)
     *
     * @param baseline 기준선 벡터
     * @param userId 사용자 ID
     */
    public void applyAllLayersFeedbackToBaseline(BaselineVector baseline, String userId) {
        try {
            Map<String, Object> layer1Feedback = layerFeedbackService.getLayer1FeedbackForUser(userId);
            Map<String, Object> layer2Feedback = layerFeedbackService.getLayer2FeedbackForUser(userId);
            Map<String, Object> layer3Feedback = layerFeedbackService.getLayer3FeedbackForUser(userId);

            int layer1Count = (int) layer1Feedback.get("feedbackCount");
            int layer2Count = (int) layer2Feedback.get("feedbackCount");
            int layer3Count = (int) layer3Feedback.get("feedbackCount");

            if (layer1Count + layer2Count + layer3Count == 0) {
                return;
            }

            // 가중 평균 계산 (Layer3: 70%, Layer2: 20%, Layer1: 10%)
            double layer1Avg = (double) layer1Feedback.get("averageRiskScore");
            double layer2Avg = (double) layer2Feedback.get("averageRiskScore");
            double layer3Avg = (double) layer3Feedback.get("averageRiskScore");

            double weightedRiskScore = (layer1Avg * 0.1) + (layer2Avg * 0.2) + (layer3Avg * 0.7);
            double highRiskThreshold = feedbackProperties.getRiskScore().getHighRiskThreshold();
            boolean hasHighRisk = weightedRiskScore >= highRiskThreshold;

            if (hasHighRisk) {
                double oldConfidence = baseline.getConfidence();

                // 신뢰도 조정: 가중 위험도에 비례하여 증가
                double confidenceBoost = 1.0 + (weightedRiskScore * 0.1);
                baseline.setConfidence(Math.min(1.0, oldConfidence * confidenceBoost));

                // 모든 Layer의 위협 카테고리 통합
                Set<String> allThreatCategories = new HashSet<>();
                allThreatCategories.addAll((List<String>) layer1Feedback.getOrDefault("threatCategories", List.of()));
                allThreatCategories.addAll((List<String>) layer2Feedback.getOrDefault("threatCategories", List.of()));
                allThreatCategories.addAll((List<String>) layer3Feedback.getOrDefault("threatCategories", List.of()));

                // 벡터 조정: 가중 위험도에 비례하여 조정
                if (!allThreatCategories.isEmpty()) {
                    double[] currentVector = baseline.getVector();
                    if (currentVector != null && currentVector.length > 0) {
                        double vectorAdjustment = 1.0 - (weightedRiskScore * 0.05);
                        for (int i = 0; i < currentVector.length; i++) {
                            currentVector[i] *= vectorAdjustment;
                        }
                        baseline.setVector(currentVector);
                    }
                }

                log.info("통합 피드백 적용 완료: userId={}, Layer1Count={}, Layer2Count={}, Layer3Count={}, " +
                    "가중 위험도={}, 신뢰도 증가: {} → {}, 위협 카테고리: {}",
                    userId, layer1Count, layer2Count, layer3Count, String.format("%.2f", weightedRiskScore),
                    oldConfidence, baseline.getConfidence(), String.join(", ", allThreatCategories));
            } else {
                log.debug("통합 피드백: userId={}, 가중 위험도={} < 임계값={}, baseline 조정 안 함",
                    userId, String.format("%.2f", weightedRiskScore), highRiskThreshold);
            }

        } catch (Exception e) {
            log.error("통합 피드백 적용 실패: userId={}", userId, e);
        }
    }
}