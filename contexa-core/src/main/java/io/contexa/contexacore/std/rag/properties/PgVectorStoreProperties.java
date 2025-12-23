package io.contexa.contexacore.std.rag.properties;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.ai.vectorstore.properties.CommonVectorStoreProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * PgVector 설정 Properties
 *
 * Spring AI CommonVectorStoreProperties를 확장하여
 * PgVector 전용 설정을 타입 안전하게 관리합니다.
 *
 * @since 1.0.0
 */
@ConfigurationProperties(prefix = "spring.ai.vectorstore.pgvector")
@Validated
@Data
@EqualsAndHashCode(callSuper = true)
public class PgVectorStoreProperties extends CommonVectorStoreProperties {

    /**
     * 인덱스 타입 (HNSW, IVFFLAT)
     */
    @NotNull
    private IndexType indexType = IndexType.HNSW;

    /**
     * 거리 계산 방식 (COSINE_DISTANCE, EUCLIDEAN_DISTANCE, NEGATIVE_INNER_PRODUCT)
     * Spring AI PgVectorStore.PgDistanceType 표준을 따릅니다.
     */
    @NotNull
    private DistanceType distanceType = DistanceType.COSINE_DISTANCE;

    /**
     * 벡터 차원 수 (128 ~ 3072)
     */
    @Min(128)
    @Max(3072)
    private int dimensions = 1024;

    /**
     * 배치 처리 크기
     */
    @Min(1)
    @Max(1000)
    private int batchSize = 100;

    /**
     * 병렬 처리 스레드 수
     */
    @Min(1)
    @Max(32)
    private int parallelThreads = 4;

    /**
     * Top-K 기본값
     */
    @Min(1)
    @Max(1000)
    private int topK = 100;

    /**
     * AI Native v3.3.0: 벡터 검색 사전 필터용 유사도 임계값 (0.0 ~ 1.0)
     *
     * 이 값은 벡터 스토어의 검색 필터로만 사용됨
     * 실제 보안 판단은 LLM이 Action(ALLOW/BLOCK/CHALLENGE/ESCALATE)으로 결정
     */
    @DecimalMin("0.0")
    @DecimalMax("1.0")
    private double similarityThreshold = 0.5;

    /**
     * HNSW 인덱스 설정
     */
    private HnswConfig hnsw = new HnswConfig();

    /**
     * IVFFLAT 인덱스 설정
     */
    private IvfflatConfig ivfflat = new IvfflatConfig();

    /**
     * 문서 처리 설정
     */
    private DocumentConfig document = new DocumentConfig();

    /**
     * HNSW 인덱스 설정
     */
    @Data
    public static class HnswConfig {
        /**
         * M 파라미터 (노드당 최대 연결 수)
         */
        @Min(4)
        @Max(64)
        private int m = 16;

        /**
         * ef_construction (인덱스 생성 시 탐색 범위)
         */
        @Min(10)
        @Max(500)
        private int efConstruction = 64;

        /**
         * ef_search (검색 시 탐색 범위)
         */
        @Min(10)
        @Max(500)
        private int efSearch = 100;
    }

    /**
     * IVFFLAT 인덱스 설정
     */
    @Data
    public static class IvfflatConfig {
        /**
         * 리스트 수 (클러스터 수)
         */
        @Min(1)
        @Max(10000)
        private int lists = 100;

        /**
         * 검색할 리스트 수
         */
        @Min(1)
        @Max(1000)
        private int probes = 10;
    }

    /**
     * 문서 처리 설정
     */
    @Data
    public static class DocumentConfig {
        /**
         * 청크 크기 (토큰 수)
         */
        @Min(100)
        @Max(10000)
        private int chunkSize = 1000;

        /**
         * 청크 오버랩 (토큰 수)
         */
        @Min(0)
        @Max(1000)
        private int chunkOverlap = 200;

        /**
         * 메타데이터 강화 활성화
         */
        private boolean enrichMetadata = true;

        /**
         * 키워드 추출 활성화
         */
        private boolean extractKeywords = true;

        /**
         * 요약 생성 활성화
         */
        private boolean generateSummary = false;
    }

    /**
     * 인덱스 타입 Enum
     */
    public enum IndexType {
        HNSW,
        IVFFLAT
    }

    /**
     * 거리 계산 방식 Enum
     * Spring AI PgVectorStore.PgDistanceType과 동일한 값 사용
     */
    public enum DistanceType {
        COSINE_DISTANCE,
        EUCLIDEAN_DISTANCE,
        NEGATIVE_INNER_PRODUCT
    }
}
