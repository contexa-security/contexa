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
     * 평균 임베딩 계산 (AI Native)
     *
     * AI Native 전환:
     * - 24시간 감쇠 규칙 제거 (시간 기반 가중치 폐지)
     * - 모든 문서에 동일한 가중치 적용 (순수 평균)
     * - 시간 정보는 LLM 컨텍스트에 별도로 전달됨
     *
     * @param documents 임베딩을 포함한 문서 리스트
     * @return 평균 임베딩 벡터
     */
    public float[] calculateWeightedEmbedding(List<Document> documents) {
        if (documents.isEmpty()) {
            return new float[embeddingDimension];
        }

        float[] averaged = new float[embeddingDimension];
        int count = 0;

        for (Document doc : documents) {
            // AI Native: 시간 기반 가중치 규칙 제거
            // 모든 문서를 동등하게 취급 (가중치 = 1.0)
            Object embeddingObj = doc.getMetadata().get("embedding");
            if (embeddingObj instanceof float[]) {
                float[] embedding = (float[]) embeddingObj;
                if (embedding.length == embeddingDimension) {
                    for (int i = 0; i < embeddingDimension; i++) {
                        averaged[i] += embedding[i];
                    }
                    count++;
                }
            }
        }

        if (count > 0) {
            for (int i = 0; i < embeddingDimension; i++) {
                averaged[i] /= count;
            }
            log.debug("[EmbeddingService][AI Native] Calculated average embedding from {} documents", count);
        }

        return averaged;
    }

    /**
     * 코사인 유사도 계산 (v3.0 - VectorSimilarityUtil 통합)
     *
     * 성능 향상:
     * - 순수 자바 대비 3-5배 속도 향상
     * - 384차원 float[]: ~0.03ms (순수 자바: ~0.15ms)
     * - 호출 빈도: 임베딩 비교마다 (초당 수천 회)
     *
     * AI Native 전환:
     * - 0.3 기본값 규칙 제거
     * - 벡터 불일치 시 NaN 반환 (분석 불가 상태 명시)
     * - LLM이 NaN을 컨텍스트로 받아 적절히 처리
     *
     * @param a 첫 번째 벡터
     * @param b 두 번째 벡터
     * @return 코사인 유사도 (0.0 ~ 1.0), 벡터 불일치 시 NaN
     */
    public double calculateCosineSimilarity(float[] a, float[] b) {
        if (a.length != b.length) {
            // AI Native: 0.3 기본값 규칙 제거
            // 벡터 불일치는 분석 불가 상태 - NaN으로 명시
            log.warn("[EmbeddingService][AI Native] Vector dimension mismatch: {} vs {} - returning NaN", a.length, b.length);
            return Double.NaN;
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
     *
     * AI Native 전환:
     * - 10% 감쇠 규칙 제거
     * - 순환 패딩 시 원본 값 그대로 사용
     * - 감쇠 적용 여부는 LLM이 컨텍스트로 판단
     */
    private float[] expandToHighDimensional(double[] vector) {
        float[] expanded = new float[embeddingDimension];
        for (int i = 0; i < expanded.length; i++) {
            if (i < vector.length) {
                expanded[i] = (float) vector[i];
            } else {
                // AI Native: 10% 감쇠 규칙 제거 - 순환 패딩 시 원본 값 유지
                expanded[i] = (float) vector[i % vector.length];
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
