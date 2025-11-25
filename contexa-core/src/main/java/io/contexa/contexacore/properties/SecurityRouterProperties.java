package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Security Router 설정
 */
@Data
@ConfigurationProperties(prefix = "security.router")
public class SecurityRouterProperties {

    /**
     * 임계값 설정
     */
    @NestedConfigurationProperty
    private ThresholdSettings threshold = new ThresholdSettings();

    /**
     * 임계값 설정
     */
    @Data
    public static class ThresholdSettings {
        private double soar = 0.9;
        private double block = 0.8;
        private double analysisConfidence = 0.6;
        private double passThrough = 0.6;
    }
}
