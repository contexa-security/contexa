package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Zero Trust 설정
 */
@Data
@ConfigurationProperties(prefix = "security.zerotrust")
public class SecurityZeroTrustProperties {

    /**
     * Zero Trust 활성화 여부
     */
    private boolean enabled = true;

    /**
     * Zero Trust 모드 (STANDARD, TRUST, REALTIME)
     */
    private String mode = "TRUST";

    /**
     * 샘플링 설정
     */
    @NestedConfigurationProperty
    private SamplingSettings sampling = new SamplingSettings();

    /**
     * HOT Path 설정
     */
    @NestedConfigurationProperty
    private HotPathSettings hotpath = new HotPathSettings();

    /**
     * 임계값 설정
     */
    @NestedConfigurationProperty
    private ThresholdsSettings thresholds = new ThresholdsSettings();

    /**
     * Redis 설정
     */
    @NestedConfigurationProperty
    private RedisSettings redis = new RedisSettings();

    /**
     * 샘플링 설정
     */
    @Data
    public static class SamplingSettings {
        private double rate = 1.0;
    }

    /**
     * HOT Path 설정
     */
    @Data
    public static class HotPathSettings {
        private boolean enabled = true;
    }

    /**
     * 임계값 설정 (AI Native v3.3.0)
     *
     * 이 임계값들은 LLM 분석 요청 라우팅용으로만 사용
     * 실제 보안 결정(ALLOW/BLOCK/CHALLENGE/ESCALATE)은 LLM이 결정
     *
     * - skip: 이 신뢰 수준 이상이면 LLM 분석 스킵 가능 (성능 최적화)
     * - optional: LLM 분석 선택적 적용
     * - required: LLM 분석 필수
     * - strict: 엄격 모드 (LLM 분석 + 추가 검증)
     */
    @Data
    public static class ThresholdsSettings {
        private double skip = 0.3;
        private double optional = 0.5;
        private double required = 0.7;
        private double strict = 0.9;
    }

    /**
     * Redis 설정
     */
    @Data
    public static class RedisSettings {
        private int timeout = 5;
    }
}
