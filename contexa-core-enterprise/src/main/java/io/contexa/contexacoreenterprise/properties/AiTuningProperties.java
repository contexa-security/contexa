package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "ai.tuning")
public class AiTuningProperties {
    private boolean enabled = true;
    @NestedConfigurationProperty
    private LearningSettings learning = new LearningSettings();
    @NestedConfigurationProperty
    private BatchSettings batch = new BatchSettings();
    @NestedConfigurationProperty
    private EvaluationSettings evaluation = new EvaluationSettings();
    @NestedConfigurationProperty
    private MinSettings min = new MinSettings();
    @NestedConfigurationProperty
    private ConfidenceSettings confidence = new ConfidenceSettings();
    @NestedConfigurationProperty
    private FalsePositiveSettings falsePositive = new FalsePositiveSettings();
    @NestedConfigurationProperty
    private FalseNegativeSettings falseNegative = new FalseNegativeSettings();

    @Data
    public static class LearningSettings { private double rate = 0.01; }
    @Data
    public static class BatchSettings { private int size = 100; }
    @Data
    public static class EvaluationSettings { private int intervalHours = 6; }
    @Data
    public static class MinSettings { private int samples = 50; }
    @Data
    public static class ConfidenceSettings { private double threshold = 0.8; }
    @Data
    public static class FalsePositiveSettings { private double penalty = 0.3; }
    @Data
    public static class FalseNegativeSettings { private double penalty = 0.7; }
}
