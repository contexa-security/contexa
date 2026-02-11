package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "policy.evolution")
public class PolicyEvolutionProperties {
    private boolean enabled = true;
    private double threshold = 0.75;
    private int minSamples = 10;
    private int retentionDays = 90;
    @NestedConfigurationProperty
    private ConfidenceSettings confidence = new ConfidenceSettings();
    @NestedConfigurationProperty
    private MaxSettings max = new MaxSettings();
    @NestedConfigurationProperty
    private EnableSettings enable = new EnableSettings();

    @Data
    public static class ConfidenceSettings { private double threshold = 0.7; }
    @Data
    public static class MaxSettings {
        private int contextSize = 10;
    }
    @Data
    public static class EnableSettings { private boolean caching = true; }
}
