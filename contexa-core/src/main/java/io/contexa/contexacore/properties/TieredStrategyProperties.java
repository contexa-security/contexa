package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.List;

@Data
@ConfigurationProperties(prefix = "spring.ai.security.tiered")
public class TieredStrategyProperties {

    private Layer1 layer1 = new Layer1();
    private Layer2 layer2 = new Layer2();

    private Truncation truncation = new Truncation();
    private Security security = new Security();
    private PromptCompression promptCompression = new PromptCompression();

    @Data
    public static class Security {

        private List<String> trustedProxies = Collections.emptyList();

        private boolean trustedProxyValidationEnabled = true;
    }

    @Data
    public static class PromptCompression {
        /**
         * Runtime compression is enabled by default so governed prompt compaction protects structured output reliability
         * when the configured budget would otherwise be exceeded.
         */
        private boolean enabled = true;
    }

    @Data
    public static class Truncation {
        private Layer1Truncation layer1 = new Layer1Truncation();
        private Layer2Truncation layer2 = new Layer2Truncation();

        @Data
        public static class Layer1Truncation {
            private int userAgent = 150;
            private int payload = 200;
            private int ragDocument = 300;
        }

        @Data
        public static class Layer2Truncation {
            private int userAgent = 150;
            private int payload = 1000;
            private int ragDocument = 500;
        }

    }

    private VectorCache vectorCache = new VectorCache();

    @Data
    public static class VectorCache {
        private int maxSize = 10000;
        private int expireMinutes = 5;
        private boolean enabled = true;
        private boolean recordStats = true;
    }

    @Data
    public static class Layer1 {
        private Rag rag = new Rag();
        private Session session = new Session();
        private Cache cache = new Cache();
        private Timeout timeout = new Timeout();
        private Prompt prompt = new Prompt();
        private int vectorSearchLimit = 12;
        private String defaultBudgetProfile = "CORTEX_L1_STANDARD";

        @Data
        public static class Prompt {

            private int maxSimilarEvents = 3;

            private int maxRagDocuments = 12;

            private boolean includeEventId = false;

            private boolean includeRawTimestamp = false;

            private boolean includeRawSessionId = false;

            private boolean includeFullUserAgent = false;
        }

        @Data
        public static class Timeout {

            private long totalMs = 4500000;

            private long llmMs = 3000000;

            private long ragMs = 1000000;
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
        private Rag rag = new Rag();
        private Cache cache = new Cache();

        private long timeoutMs = 10000;
        private boolean enableSoar = false;
        private int ragTopK = 10;
        private String defaultBudgetProfile = "CORTEX_L2_STANDARD";

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

