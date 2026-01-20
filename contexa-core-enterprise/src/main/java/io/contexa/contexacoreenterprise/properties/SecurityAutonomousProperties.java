package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;


@Data
@ConfigurationProperties(prefix = "security.autonomous")
public class SecurityAutonomousProperties {

    
    @NestedConfigurationProperty
    private LearningSettings learning = new LearningSettings();

    
    @Data
    public static class LearningSettings {
        private boolean enabled = true;

        @NestedConfigurationProperty
        private EvolutionSettings evolution = new EvolutionSettings();

        @Data
        public static class EvolutionSettings {
            private double confidenceThreshold = 0.8;
            private int maxProposals = 100;
            private int slowPolicyThresholdMs = 1000;
        }
    }
}
