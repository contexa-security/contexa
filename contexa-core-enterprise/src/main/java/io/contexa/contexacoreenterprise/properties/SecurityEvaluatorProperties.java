package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;


@Data
@ConfigurationProperties(prefix = "security.evaluator")
public class SecurityEvaluatorProperties {

    
    @NestedConfigurationProperty
    private ConsensusSettings consensus = new ConsensusSettings();

    
    private int minStrategies = 3;

    
    private int timeoutMs = 500;

    
    private boolean parallelEnabled = true;

    
    @NestedConfigurationProperty
    private WeightSettings weight = new WeightSettings();

    
    @Data
    public static class ConsensusSettings {
        private double threshold = 0.75;
    }

    
    @Data
    public static class WeightSettings {
        private double behavioral = 0.3;
        private double mitre = 0.2;
        private double nist = 0.1;
    }
}
