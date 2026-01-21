package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "security.zerotrust")
public class SecurityZeroTrustProperties {

    private boolean enabled = true;

    private String mode = "TRUST";

    @NestedConfigurationProperty
    private SamplingSettings sampling = new SamplingSettings();

    @NestedConfigurationProperty
    private HotPathSettings hotpath = new HotPathSettings();

    @NestedConfigurationProperty
    private ThresholdsSettings thresholds = new ThresholdsSettings();

    @NestedConfigurationProperty
    private RedisSettings redis = new RedisSettings();

    @Data
    public static class SamplingSettings {
        private double rate = 1.0;
    }

    @Data
    public static class HotPathSettings {
        private boolean enabled = true;
    }

    @Data
    public static class ThresholdsSettings {
        private double skip = 0.3;
        private double optional = 0.5;
        private double required = 0.7;
        private double strict = 0.9;
    }

    @Data
    public static class RedisSettings {
        private int timeout = 5;
    }
}
