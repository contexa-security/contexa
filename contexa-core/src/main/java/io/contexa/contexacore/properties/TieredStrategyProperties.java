package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "spring.ai.security.tiered")
public class TieredStrategyProperties {

    private Layer1 layer1 = new Layer1();
    private Layer2 layer2 = new Layer2();
    
    private Truncation truncation = new Truncation();
    private Security security = new Security();

    @Data
    public static class Security {
        
        private java.util.List<String> trustedProxies = java.util.Collections.emptyList();

        private boolean trustedProxyValidationEnabled = true;
    }

    @Data
    public static class Truncation {
        private Layer1Truncation layer1 = new Layer1Truncation();
        private Layer2Truncation layer2 = new Layer2Truncation();

        @Data
        public static class Layer1Truncation {
            private int userAgent = 150;
            private int payload = 200;
            private int authzReason = 80;
            private int baselineContext = 150;
            private int ragDocument = 300;  
            
        }

        @Data
        public static class Layer2Truncation {
            private int userAgent = 150;
            private int payload = 1000;
            private int ragDocument = 500;
            private int reasoning = 100;
            
        }

    }

    @Data
    public static class Layer1 {
        private Monitoring monitoring = new Monitoring();
        private Rag rag = new Rag();
        private Session session = new Session();
        private Cache cache = new Cache();
        private Timeout timeout = new Timeout();
        private Prompt prompt = new Prompt();

        @Data
        public static class Prompt {
            
            private int maxSimilarEvents = 3;

            private int maxRagDocuments = 5;

            private int maxDescriptionLength = 200;

            private int maxRecentActions = 5;
        }

        @Data
        public static class Timeout {
            
            private long totalMs = 15000;

            private long llmMs = 30000;

            private long vectorSearchMs = 3000;

            private long redisMs = 1000;

            private long baselineMs = 2000;
        }

        @Data
        public static class Monitoring {
            
            private double highRiskThreshold = 0.7;

            private double lowConfidenceThreshold = 0.3;

            private double lowRiskThreshold = 0.3;
        }

        @Data
        public static class Rag {
            
            private double similarityThreshold = 0.5;
        }

        @Data
        public static class Session {
            
            private int maxRecentActions = 100;
        }

        @Data
        public static class Cache {
            
            private int maxSize = 1000;

            private int ttlMinutes = 30;
        }
    }

    @Data
    public static class Layer2 {
        private Session session = new Session();
        private Rag rag = new Rag();
        private Cache cache = new Cache();
        private Prompt prompt = new Prompt();

        @Data
        public static class Prompt {
            
            private int maxSimilarEvents = 3;

            private int maxRagDocuments = 5;

            private int maxDescriptionLength = 200;

            private int maxRecentActions = 5;

            private int maxSimilarIncidents = 3;
        }

        @Data
        public static class Session {
            
            private int maxRecentActions = 100;
        }

        @Data
        public static class Cache {
            
            private int maxSize = 1000;

            private int ttlMinutes = 30;
        }

        @Data
        public static class Rag {
            
            private double similarityThreshold = 0.5;

        }
    }

}
