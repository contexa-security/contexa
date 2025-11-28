package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacommon.hcad.util.VectorSimilarityUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;

/**
 * 임베딩 생성 및 캐싱 서비스
 *
 * HCADVectorIntegrationService 에서 추출된 임베딩 관련 기능:
 * - HCADContext → 고차원 임베딩 변환
 * - 임베딩 캐싱 (Redis)
 * - 가중 평균 임베딩 계산
 * - 코사인 유사도 계산
 *
 * 성능 최적화:
 * - Redis 기반 L1 캐시 (1시간 TTL)
 * - 컨텍스트별 캐시 키 생성
 *
 * @author contexa
 * @since 3.0
 */
@Slf4j
@RequiredArgsConstructor
public class EmbeddingService {

    private final RedisTemplate<String, Object> redisTemplate;

    @Autowired(required = false)
    private EmbeddingModel embeddingModel;

    @Value("${hcad.vector.embedding-dimension:384}")
    private int embeddingDimension;

    @Value("${hcad.vector.cache-ttl-hours:24}")
    private long cacheTtlHours;

    /**
     * HCADContext를 고차원 임베딩으로 변환
     *
     * @param context HCAD 컨텍스트
     * @return 384차원 임베딩 벡터
     */
    @Cacheable(value = "hcadEmbeddings", key = "#context.userId + ':' + #context.sessionId")
    public float[] generateContextEmbedding(HCADContext context) {
        try {
            if (embeddingModel == null) {
                // 임베딩 모델이 없으면 기본 벡터 확장
                log.debug("[EmbeddingService] No embedding model available, using fallback expansion");
                return expandToHighDimensional(context.toVector());
            }

            // 컨텍스트를 텍스트로 변환
            String contextText = contextToText(context);

            // 임베딩 생성
            List<float[]> embeddings = embeddingModel.embed(List.of(contextText));
            if (!embeddings.isEmpty()) {
                float[] embedding = embeddings.get(0);

                // Redis에 캐싱
                cacheEmbedding(context.getUserId(), context.getSessionId(), embedding);

                log.debug("[EmbeddingService] Generated embedding for userId={}, sessionId={}",
                    context.getUserId(), context.getSessionId());

                return embedding;
            }

        } catch (Exception e) {
            log.error("[EmbeddingService] Failed to generate embedding: {}", e.getMessage());
        }

        // 폴백: 기본 벡터 확장
        return expandToHighDimensional(context.toVector());
    }

    /**
     * 평균 임베딩 계산
     *
     * @param documents 임베딩을 포함한 문서 리스트
     * @return 평균 임베딩 벡터
     */
    public float[] calculateAverageEmbedding(List<Document> documents) {
        if (documents.isEmpty()) {
            return new float[embeddingDimension];
        }

        float[] average = new float[embeddingDimension];
        int count = 0;

        for (Document doc : documents) {
            // 문서에서 임베딩 추출 (메타데이터에 저장되어 있다고 가정)
            Object embeddingObj = doc.getMetadata().get("embedding");
            if (embeddingObj instanceof float[]) {
                float[] embedding = (float[]) embeddingObj;
                if (embedding.length == embeddingDimension) {
                    for (int i = 0; i < embeddingDimension; i++) {
                        average[i] += embedding[i];
                    }
                    count++;
                }
            }
        }

        if (count > 0) {
            for (int i = 0; i < embeddingDimension; i++) {
                average[i] /= count;
            }
            log.debug("[EmbeddingService] Calculated average embedding from {} documents", count);
        }

        return average;
    }

    /**
     * 가중 평균 임베딩 계산 (최신 문서일수록 높은 가중치)
     *
     * @param documents 임베딩을 포함한 문서 리스트
     * @return 가중 평균 임베딩 벡터
     */
    public float[] calculateWeightedEmbedding(List<Document> documents) {
        if (documents.isEmpty()) {
            return new float[embeddingDimension];
        }

        float[] weighted = new float[embeddingDimension];
        float totalWeight = 0;

        for (Document doc : documents) {
            // 최신 문서일수록 높은 가중치 (지수 감쇠)
            Object timestampObj = doc.getMetadata().get("timestamp");
            float weight = 1.0f;
            if (timestampObj != null) {
                try {
                    LocalDateTime timestamp = LocalDateTime.parse(timestampObj.toString());
                    long hoursAgo = Duration.between(timestamp, LocalDateTime.now()).toHours();
                    weight = (float) Math.exp(-hoursAgo / 24.0); // 24시간마다 1/e로 감쇠
                } catch (Exception e) {
                    // 타임스탬프 파싱 실패 시 기본 가중치 사용
                    log.debug("[EmbeddingService] Failed to parse timestamp, using default weight");
                }
            }

            Object embeddingObj = doc.getMetadata().get("embedding");
            if (embeddingObj instanceof float[]) {
                float[] embedding = (float[]) embeddingObj;
                if (embedding.length == embeddingDimension) {
                    for (int i = 0; i < embeddingDimension; i++) {
                        weighted[i] += embedding[i] * weight;
                    }
                    totalWeight += weight;
                }
            }
        }

        if (totalWeight > 0) {
            for (int i = 0; i < embeddingDimension; i++) {
                weighted[i] /= totalWeight;
            }
            log.debug("[EmbeddingService] Calculated weighted embedding with total weight={}", totalWeight);
        }

        return weighted;
    }

    /**
     * 코사인 유사도 계산 (v3.0 - VectorSimilarityUtil 통합)
     * 성능 향상:
     * - 순수 자바 대비 3-5배 속도 향상
     * - 384차원 float[]: ~0.03ms (순수 자바: ~0.15ms)
     * - 호출 빈도: 임베딩 비교마다 (초당 수천 회)
     *
     * @param a 첫 번째 벡터
     * @param b 두 번째 벡터
     * @return 코사인 유사도 (0.0 ~ 1.0)
     */
    public double calculateCosineSimilarity(float[] a, float[] b) {
        if (a.length != b.length) {
            log.warn("[EmbeddingService] Vector dimension mismatch: {} vs {}", a.length, b.length);
            return 0.3;  // Zero Trust: 벡터 불일치 = 낮은 유사도
        }

        // VectorSimilarityUtil 통합 사용
        return VectorSimilarityUtil.cosineSimilarity(a, b);
    }

    /**
     * 캐시된 사용자 정상 임베딩 조회
     *
     * @param userId 사용자 ID
     * @return 캐시된 임베딩 (없으면 null)
     */
    public float[] getCachedNormalEmbedding(String userId) {
        try {
            String key = "hcad:baseline:v2:" + userId;
            return (float[]) redisTemplate.opsForValue().get(key);
        } catch (Exception e) {
            log.debug("[EmbeddingService] Failed to retrieve cached normal embedding for userId={}", userId);
            return null;
        }
    }

    /**
     * 정상 임베딩 캐싱
     *
     * @param userId 사용자 ID
     * @param embedding 임베딩 벡터
     */
    public void cacheNormalEmbedding(String userId, float[] embedding) {
        try {
            String key = "hcad:baseline:v2:" + userId;
            redisTemplate.opsForValue().set(key, embedding, Duration.ofHours(cacheTtlHours));
            log.debug("[EmbeddingService] Cached normal embedding for userId={}", userId);
        } catch (Exception e) {
            log.warn("[EmbeddingService] Failed to cache normal embedding for userId={}", userId);
        }
    }

    // ==================== Private Helper Methods ====================

    /**
     * HCADContext를 텍스트로 변환
     */
    private String contextToText(HCADContext context) {
        StringBuilder sb = new StringBuilder();
        sb.append("User: ").append(context.getUserId()).append(" ");
        sb.append("Path: ").append(context.getRequestPath()).append(" ");
        sb.append("Method: ").append(context.getHttpMethod()).append(" ");
        sb.append("IP: ").append(context.getRemoteIp()).append(" ");
        sb.append("Time: ").append(context.getTimestamp()).append(" ");
        sb.append("Trust: ").append(context.getCurrentTrustScore()).append(" ");
        sb.append("NewSession: ").append(context.getIsNewSession()).append(" ");
        sb.append("NewDevice: ").append(context.getIsNewDevice()).append(" ");
        sb.append("RecentRequests: ").append(context.getRecentRequestCount());
        return sb.toString();
    }

    /**
     * 저차원 벡터를 고차원으로 확장 (폴백용)
     */
    private float[] expandToHighDimensional(double[] vector) {
        float[] expanded = new float[embeddingDimension];
        for (int i = 0; i < expanded.length; i++) {
            if (i < vector.length) {
                expanded[i] = (float) vector[i];
            } else {
                // 순환 패딩 (10% 감쇠)
                expanded[i] = (float) vector[i % vector.length] * 0.1f;
            }
        }
        return expanded;
    }

    /**
     * 세션별 임베딩 캐싱 (단기 캐시, 1시간 TTL)
     */
    private void cacheEmbedding(String userId, String sessionId, float[] embedding) {
        try {
            String key = String.format("hcad:embedding:session:%s:%s", userId, sessionId);
            redisTemplate.opsForValue().set(key, embedding, Duration.ofHours(1));
        } catch (Exception e) {
            log.debug("[EmbeddingService] Failed to cache session embedding");
        }
    }
}
