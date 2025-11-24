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
     * 임계값 설정
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
