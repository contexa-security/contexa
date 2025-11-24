package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Security Session 설정
 */
@Data
@ConfigurationProperties(prefix = "security.session")
public class SecuritySessionProperties {

    /**
     * 세션 생성 설정
     */
    @NestedConfigurationProperty
    private CreateSettings create = new CreateSettings();

    /**
     * 헤더 설정
     */
    @NestedConfigurationProperty
    private HeaderSettings header = new HeaderSettings();

    /**
     * Bearer 설정
     */
    @NestedConfigurationProperty
    private BearerSettings bearer = new BearerSettings();

    /**
     * 세션 하이재킹 설정
     */
    @NestedConfigurationProperty
    private HijackSettings hijack = new HijackSettings();

    /**
     * 위협 설정
     */
    @NestedConfigurationProperty
    private ThreatSettings threat = new ThreatSettings();

    /**
     * 세션 생성 설정
     */
    @Data
    public static class CreateSettings {
        private boolean allowed = true;
    }

    /**
     * 헤더 설정
     */
    @Data
    public static class HeaderSettings {
        private String name = "X-Auth-Token";
    }

    /**
     * Bearer 설정
     */
    @Data
    public static class BearerSettings {
        private boolean enabled = true;
    }

    /**
     * 세션 하이재킹 설정
     */
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

    /**
     * 위협 설정
     */
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
