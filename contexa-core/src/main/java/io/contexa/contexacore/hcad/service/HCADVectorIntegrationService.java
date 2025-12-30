package io.contexa.contexacore.hcad.service;

import io.contexa.contexacore.autonomous.config.FeedbackIntegrationProperties;
import io.contexa.contexacore.autonomous.tiered.feedback.LayerFeedbackService;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.hcad.domain.HCADContext;
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

    @Value("${hcad.vector.max-cached-embeddings:1000}")
    private int maxCachedEmbeddings;

    // AI Native 전환: similarityThreshold, scenarioDetectionEnabled 제거
    // - 모든 판단은 LLM에게 위임
    // - 시나리오 분류도 LLM이 직접 결정

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
                // AI Native v3.0: highDimensionalEmbedding, embeddingVersion, embeddingUpdatedAt 설정 제거
                // - BaselineVector에서 해당 필드 제거됨
                // - LLM 분석에 불필요한 데이터

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

                // AI Native: 유사도를 그대로 반환 (LLM 컨텍스트로 전달될 정보)
                // 임계값 기반 조정 로직 제거 - 모든 판단은 LLM에게 위임
                return similarity;
            }

        } catch (Exception e) {
            log.error("실시간 이상 점수 계산 실패: {}", e.getMessage());
        }

        // AI Native: 계산 실패 시 null 반환하여 LLM이 컨텍스트 부재 상황을 인지하도록 함
        // 기존 0.5 기본값 제거 - 플랫폼이 임의로 값을 생성하지 않음
        return Double.NaN;
    }

    /**
     * 시나리오 컨텍스트 정보 추출
     *
     * AI Native 전환: 규칙 기반 시나리오 분류 제거
     * - 시나리오 결정은 LLM이 직접 수행
     * - 이 메서드는 원시 컨텍스트 정보만 JSON 형태로 반환
     * - LLM에게 전달될 컨텍스트에 포함됨
     *
     * @param context HCAD 컨텍스트
     * @return 원시 컨텍스트 정보 (JSON 형식)
     * @deprecated 시나리오 분류는 LLM이 직접 수행합니다. 이 메서드는 컨텍스트 정보 추출용으로만 사용하세요.
     */
    @Deprecated
    public String detectScenario(HCADContext context) {
        // AI Native: 규칙 기반 시나리오 분류 제거
        // 원시 컨텍스트 정보만 JSON 형태로 반환하여 LLM 컨텍스트에 포함
        StringBuilder contextInfo = new StringBuilder();
        contextInfo.append("{");

        // 시간 정보 (LLM이 판단할 수 있도록 원시 데이터 제공)
        if (context.getTimestamp() != null) {
            int hour = context.getTimestamp().atZone(java.time.ZoneId.systemDefault()).getHour();
            int dayOfWeek = context.getTimestamp().atZone(java.time.ZoneId.systemDefault()).getDayOfWeek().getValue();
            contextInfo.append("\"hour\":").append(hour).append(",");
            contextInfo.append("\"dayOfWeek\":").append(dayOfWeek).append(",");
        }

        // IP 정보 (LLM이 판단할 수 있도록 원시 데이터 제공)
        if (context.getRemoteIp() != null) {
            contextInfo.append("\"remoteIp\":\"").append(context.getRemoteIp()).append("\",");
        }

        // User-Agent 정보 (LLM이 판단할 수 있도록 원시 데이터 제공)
        if (context.getUserAgent() != null) {
            contextInfo.append("\"userAgent\":\"").append(context.getUserAgent().replace("\"", "\\\"")).append("\",");
        }

        // 마지막 쉼표 제거 및 닫기
        String result = contextInfo.toString();
        if (result.endsWith(",")) {
            result = result.substring(0, result.length() - 1);
        }
        result += "}";

        return result;
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
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Map<Object, Object> analysis = redisTemplate.opsForHash().entries(analysisKey);

            if (analysis == null || analysis.isEmpty()) {
                log.debug("Cold Path 분석 결과 없음: userId={}", userId);
                return;
            }

            // AI Native: riskScore 추출 및 저장 (threatScoreAdjustment 대체)
            Object riskScoreObj = analysis.get("riskScore");
            if (riskScoreObj != null) {
                double riskScore = Double.parseDouble(riskScoreObj.toString());

                // Hot Path에서 사용할 Redis 키에 저장 (ZeroTrustRedisKeys 사용)
                String riskScoreKey = "threat_score:" + userId;
                redisTemplate.opsForValue().set(
                    riskScoreKey,
                    riskScore,
                    Duration.ofHours(1) // 1시간 TTL
                );

                log.info("Phase 2 완료: userId={}, riskScore={}",
                    userId, String.format("%.3f", riskScore));
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
            // AI Native 전환: similarityThreshold 제거
            // - 모든 유사 패턴을 검색하여 LLM 컨텍스트에 포함
            // - 임계값 기반 필터링은 LLM이 직접 판단
            SearchRequest searchRequest = SearchRequest.builder()
                .query(String.format("userId:%s AND type:normal_pattern", userId))
                .topK(5)
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

    // AI Native v3.0: updateScenarioPatterns() 제거
    // - BaselineVector.updateScenarioPattern() 제거됨
    // - 시나리오 분류는 LLM이 직접 수행

    /**
     * 시나리오별 임베딩 추출
     * EmbeddingService 위임
     */
    private Map<String, float[]> extractScenarioEmbeddings(List<Document> patterns) {
        Map<String, List<Document>> scenarioGroups = patterns.stream()
            .collect(Collectors.groupingBy((Document doc) -> detectScenarioFromDocument(doc)));

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

    /**
     * Document에서 시나리오 메타데이터 추출
     *
     * AI Native 전환: 규칙 기반 시나리오 결정 제거
     * - Document 메타데이터에 이미 존재하는 scenario 필드를 직접 반환
     * - 시나리오가 없으면 "unknown" 반환 (LLM이 컨텍스트로 판단)
     */
    private String detectScenarioFromDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        // AI Native: 메타데이터에서 scenario 필드 직접 추출
        // 시나리오 결정 규칙 제거 - LLM이 직접 판단
        Object scenarioObj = metadata.get("scenario");
        if (scenarioObj != null) {
            return scenarioObj.toString();
        }

        // scenario 필드가 없으면 "unknown" 반환
        // LLM이 다른 컨텍스트 정보로 판단
        return "unknown";
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

    // AI Native 전환: isInternalIp() 제거
    // - IP 기반 내부/외부 판단은 LLM이 컨텍스트로 직접 수행
    // - IP 주소 원시 데이터를 LLM에게 전달

    // AI Native v3.1: 다음 메서드 삭제 - 죽은 코드
    // - applyLayer3FeedbackToBaseline() - 외부 호출 없음
    // - applyAllLayersFeedbackToBaseline() - 외부 호출 없음
    // - feedbackMetadata 필드 저장/검색 구현 없음 (saveBaseline/getBaseline에서 처리 안 함)
    // - 데이터 흐름 전체가 미구현/죽은 코드
}