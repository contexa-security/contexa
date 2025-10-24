package io.contexa.contexacore.autonomous.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "security.feedback")
public class FeedbackIntegrationProperties {

    private RiskScore riskScore = new RiskScore();
    private Redis redis = new Redis();
    private Pattern pattern = new Pattern();

    @Data
    public static class RiskScore {
        private double indexingThreshold = 7.0;
        private double hotSyncThreshold = 8.0;
        private double highRiskThreshold = 8.0;
    }

    @Data
    public static class Redis {
        private String patternKeyPrefix = "layer3:pattern:";
        private String feedbackKeyPrefix = "layer3:feedback:";
        private String layer1FeedbackKeyPrefix = "layer1:feedback:";
        private String layer2FeedbackKeyPrefix = "layer2:feedback:";
    }

    @Data
    public static class Pattern {
        private int maxRecentPatterns = 10;
    }
}