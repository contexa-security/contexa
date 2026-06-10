package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "contexa.security.zerotrust")
public class SecurityZeroTrustProperties {

    private boolean enabled = true;

    private SecurityMode mode = SecurityMode.ENFORCE;

    private int maxBlockMfaAttempts = 2;

    public enum SecurityMode {
        SHADOW,
        ENFORCE;

        public boolean isEnforcementEnabled() {
            return this == ENFORCE;
        }
    }

    public boolean isEnforcementEnabled() {
        return mode.isEnforcementEnabled();
    }

    @NestedConfigurationProperty
    private SamplingSettings sampling = new SamplingSettings();

    @NestedConfigurationProperty
    private HotPathSettings hotpath = new HotPathSettings();

    @NestedConfigurationProperty
    private ThresholdsSettings thresholds = new ThresholdsSettings();

    @NestedConfigurationProperty
    private ProtectableSettings protectable = new ProtectableSettings();

    @NestedConfigurationProperty
    private RedisSettings redis = new RedisSettings();

    @NestedConfigurationProperty
    private ThreatSettings threat = new ThreatSettings();

    @NestedConfigurationProperty
    private CacheSettings cache = new CacheSettings();

    @NestedConfigurationProperty
    private SessionSettings session = new SessionSettings();

    @Data
    public static class ThreatSettings {
        private double initial = 0.3;
    }

    @Data
    public static class CacheSettings {
        private int ttlHours = 24;
        private int sessionTtlMinutes = 30;
        private int invalidatedTtlMinutes = 60;
    }

    @Data
    public static class SessionSettings {
        private boolean trackingEnabled = true;
    }

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
    public static class ProtectableSettings {
        private long rapidReentryWindowMs = 5000;
    }

    @Data
    public static class RedisSettings {
        private int timeout = 5000;
        private int updateIntervalSeconds = 30;
    }
}
