package io.contexa.contexacommon.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Trust Tier 기능 설정 Properties
 *
 * 사용자 application.yml 설정 예시:
 * <pre>
 * security:
 *   trust-tier:
 *     enabled: true
 *     cache:
 *       ttl-minutes: 5
 *     defaults:
 *       trust-score: 0.5
 *     thresholds:
 *       tier1: 0.8
 *       tier2: 0.6
 *       tier3: 0.4
 * </pre>
 */
@Data
@ConfigurationProperties(prefix = "security.trust-tier")
public class SecurityTrustTierProperties {

    /**
     * Trust Tier 기능 활성화 여부
     * 기본값: false
     */
    private boolean enabled = false;

    /**
     * Redis 캐시 설정
     */
    private CacheProperties cache = new CacheProperties();

    /**
     * 기본값 설정
     */
    private DefaultProperties defaults = new DefaultProperties();

    /**
     * Tier 임계값 설정
     */
    private ThresholdProperties thresholds = new ThresholdProperties();

    @Data
    public static class CacheProperties {
        /**
         * Trust Tier 캐시 TTL (분 단위)
         * 기본값: 5분
         */
        private int ttlMinutes = 5;
    }

    @Data
    public static class DefaultProperties {
        /**
         * 초기 Trust Score
         * 기본값: 0.5 (중립)
         */
        private double trustScore = 0.5;
    }

    @Data
    public static class ThresholdProperties {
        /**
         * TIER_1 임계값 (Full Access)
         * 기본값: 0.8 이상
         */
        private double tier1 = 0.8;

        /**
         * TIER_2 임계값 (Limited Sensitive Operations)
         * 기본값: 0.6 이상
         */
        private double tier2 = 0.6;

        /**
         * TIER_3 임계값 (Read-Only)
         * 기본값: 0.4 이상
         */
        private double tier3 = 0.4;

        // TIER_4는 0.4 미만 (Minimal Access)
    }
}
