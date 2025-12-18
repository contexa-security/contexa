package io.contexa.contexacommon.cache;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Contexa 통합 캐시 설정 Properties
 *
 * 2-Level 캐시 아키텍처:
 * - L1: Caffeine (로컬 인메모리)
 * - L2: Redis (분산)
 * - Pub/Sub: 분산 캐시 무효화
 *
 * 설정 예시:
 * <pre>
 * contexa:
 *   cache:
 *     type: hybrid          # local | redis | hybrid
 *     local:
 *       max-size: 1000
 *       default-ttl-seconds: 60
 *     redis:
 *       default-ttl-seconds: 300
 *       key-prefix: "contexa:cache:"
 *     pubsub:
 *       enabled: true
 *       channel: "contexa:cache:invalidation"
 * </pre>
 *
 * @since 0.1.0-ALPHA
 */
@Data
@ConfigurationProperties(prefix = "contexa.cache")
public class ContexaCacheProperties {

    /**
     * 캐시 타입
     */
    public enum CacheType {
        /**
         * Caffeine 로컬 캐시만 사용 (단일 노드 환경)
         */
        LOCAL,

        /**
         * Redis만 사용 (기존 @Cacheable 방식과 호환)
         */
        REDIS,

        /**
         * L1 Caffeine + L2 Redis + Pub/Sub 분산 무효화 (분산 환경 권장)
         */
        HYBRID
    }

    /**
     * 캐시 타입 (기본값: REDIS - 기존 방식 유지)
     */
    private CacheType type = CacheType.REDIS;

    /**
     * L1 로컬 캐시 설정 (Caffeine)
     */
    private LocalConfig local = new LocalConfig();

    /**
     * L2 Redis 캐시 설정
     */
    private RedisConfig redis = new RedisConfig();

    /**
     * Pub/Sub 분산 무효화 설정
     */
    private PubSubConfig pubsub = new PubSubConfig();

    /**
     * 도메인별 TTL 설정
     */
    private DomainConfig domains = new DomainConfig();

    /**
     * L1 로컬 캐시 설정 (Caffeine)
     */
    @Data
    public static class LocalConfig {
        /**
         * 최대 캐시 엔트리 수 (기본값: 1000)
         */
        private int maxSize = 1000;

        /**
         * 기본 TTL (초, 기본값: 60초)
         */
        private int defaultTtlSeconds = 60;
    }

    /**
     * L2 Redis 캐시 설정
     */
    @Data
    public static class RedisConfig {
        /**
         * 기본 TTL (초, 기본값: 300초 = 5분)
         */
        private int defaultTtlSeconds = 300;

        /**
         * Redis 키 프리픽스 (기본값: "contexa:cache:")
         */
        private String keyPrefix = "contexa:cache:";
    }

    /**
     * Pub/Sub 분산 무효화 설정
     */
    @Data
    public static class PubSubConfig {
        /**
         * Pub/Sub 활성화 여부 (기본값: true)
         */
        private boolean enabled = true;

        /**
         * 무효화 채널명 (기본값: "contexa:cache:invalidation")
         */
        private String channel = "contexa:cache:invalidation";
    }

    /**
     * 도메인별 TTL 설정
     */
    @Data
    public static class DomainConfig {
        /**
         * 사용자 정보 캐시 TTL (기본값: 1시간)
         */
        private TtlConfig users = new TtlConfig(3600, 3600);

        /**
         * 역할 정보 캐시 TTL (기본값: 4시간)
         */
        private TtlConfig roles = new TtlConfig(14400, 14400);

        /**
         * 권한 정보 캐시 TTL (기본값: 8시간)
         */
        private TtlConfig permissions = new TtlConfig(28800, 28800);

        /**
         * 그룹 정보 캐시 TTL (기본값: 4시간)
         * 주의: 그룹 멤버 변경이 빈번하면 짧게 설정
         */
        private TtlConfig groups = new TtlConfig(14400, 14400);

        /**
         * 정책 캐시 TTL (기본값: L1 30초, L2 5분)
         * 보안상 빠른 반영 필요
         */
        private TtlConfig policies = new TtlConfig(30, 300);

        /**
         * SOAR 관련 캐시 TTL (기본값: 15분)
         */
        private TtlConfig soar = new TtlConfig(900, 900);

        /**
         * HCAD 행동 패턴 캐시 TTL (기본값: 24시간)
         */
        private TtlConfig hcad = new TtlConfig(86400, 86400);
    }

    /**
     * L1/L2 TTL 설정
     */
    @Data
    public static class TtlConfig {
        /**
         * L1 로컬 캐시 TTL (초)
         */
        private int localTtlSeconds;

        /**
         * L2 Redis 캐시 TTL (초)
         */
        private int redisTtlSeconds;

        public TtlConfig() {
            // 기본 생성자
        }

        public TtlConfig(int localTtlSeconds, int redisTtlSeconds) {
            this.localTtlSeconds = localTtlSeconds;
            this.redisTtlSeconds = redisTtlSeconds;
        }
    }
}
