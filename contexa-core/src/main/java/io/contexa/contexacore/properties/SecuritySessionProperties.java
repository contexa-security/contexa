package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "security.session")
public class SecuritySessionProperties {

    @NestedConfigurationProperty
    private CreateSettings create = new CreateSettings();

    @NestedConfigurationProperty
    private HeaderSettings header = new HeaderSettings();

    @NestedConfigurationProperty
    private BearerSettings bearer = new BearerSettings();

    @NestedConfigurationProperty
    private HijackSettings hijack = new HijackSettings();

    @NestedConfigurationProperty
    private CookieSettings cookie = new CookieSettings();

    @NestedConfigurationProperty
    private ThreatSettings threat = new ThreatSettings();

    @Data
    public static class CookieSettings {
        private String name = "SESSION";
    }

    @Data
    public static class CreateSettings {
        private boolean allowed = true;
    }

    @Data
    public static class HeaderSettings {
        private String name = "X-Auth-Token";
    }

    @Data
    public static class BearerSettings {
        private boolean enabled = true;
    }

    @Data
    public static class HijackSettings {
        private String channel = "security:session:hijack:event";

        @NestedConfigurationProperty
        private DetectionSettings detection = new DetectionSettings();

        @Data
        public static class DetectionSettings {
            private boolean enabled = true;
        }
    }

    @Data
    public static class ThreatSettings {
        private double ipChangeRisk = 0.4;
        private double uaChangeRisk = 0.3;
        private int rapidAccessThresholdMs = 100;
        private double rapidAccessRisk = 0.2;

        @NestedConfigurationProperty
        private ThresholdsSettings thresholds = new ThresholdsSettings();

        @Data
        public static class ThresholdsSettings {
            private double monitoring = 0.5;
            private double gracePeriod = 0.7;
            private double invalidation = 0.9;
        }
    }
}
