package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "learning.engine")
public class LearningEngineProperties {
    private boolean enabled = true;
    private int batchSize = 50;
    private double learningRate = 0.01;
    private double confidenceThreshold = 0.75;
    private int retentionHours = 168;
    private int patternMinOccurrences = 3;
}
