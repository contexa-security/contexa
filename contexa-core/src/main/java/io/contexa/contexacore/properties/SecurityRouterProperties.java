package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "security.router")
public class SecurityRouterProperties {

    @NestedConfigurationProperty
    private ThresholdSettings threshold = new ThresholdSettings();

    @Data
    public static class ThresholdSettings {
        private double soar = 0.9;
        private double block = 0.8;
        private double analysisConfidence = 0.6;
        private double passThrough = 0.6;
    }
}
