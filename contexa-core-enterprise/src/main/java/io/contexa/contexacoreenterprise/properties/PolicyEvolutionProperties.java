package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "policy.evolution")
public class PolicyEvolutionProperties {
    private boolean enabled = true;
    private double threshold = 0.75;
    @NestedConfigurationProperty
    private ConfidenceSettings confidence = new ConfidenceSettings();
    @NestedConfigurationProperty
    private MaxSettings max = new MaxSettings();
    @NestedConfigurationProperty
    private EnableSettings enable = new EnableSettings();
    @NestedConfigurationProperty
    private DefaultSettings defaults = new DefaultSettings();

    @Data
    public static class ConfidenceSettings {
        private double threshold = 0.7;
        // Below this confidence, risk is increased by +1
        private double lowThreshold = 0.5;
        // Above this confidence, risk is decreased by -1
        private double highThreshold = 0.8;
    }
    @Data
    public static class MaxSettings {
        private int contextSize = 10;
        // Maximum similar cases to include in AI prompt
        private int promptSimilarCases = 3;
    }
    @Data
    public static class EnableSettings { private boolean caching = true; }
    @Data
    public static class DefaultSettings {
        // Neutral default when AI response parsing fails (midpoint of 0.0-1.0)
        private double expectedImpact = 0.5;
    }
}
