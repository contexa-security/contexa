package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.List;

@Data
@ConfigurationProperties(prefix = "contexa.security.tiered")
public class TieredStrategyProperties {

    private Layer1 layer1 = new Layer1();
    private Layer2 layer2 = new Layer2();

    private Truncation truncation = new Truncation();
    private Security security = new Security();
    private PromptCompression promptCompression = new PromptCompression();
    private PromptRuntime promptRuntime = new PromptRuntime();

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
    public static class PromptRuntime {
        /**
         * When disabled, runtime falls back to validated converter mode but never re-enables raw semantic fallback.
         */
        private boolean nativeStructuredOutputEnabled = true;
        private List<String> nativeStructuredOutputDisabledProfiles = Collections.emptyList();
        /**
         * Prompt runtime telemetry remains on by default for official verification and rollout diagnostics.
         */
        private boolean telemetryEnabled = true;

        public boolean isNativeStructuredOutputEnabledForProfile(String profileKey) {
            if (!nativeStructuredOutputEnabled) {
                return false;
            }
            if (profileKey == null || profileKey.isBlank()) {
                return true;
            }
            return nativeStructuredOutputDisabledProfiles == null
                    || nativeStructuredOutputDisabledProfiles.stream()
                    .filter(value -> value != null && !value.isBlank())
                    .noneMatch(value -> value.trim().equalsIgnoreCase(profileKey.trim()));
        }
    }

    @Data
    public static class Truncation {
        private Layer1Truncation layer1 = new Layer1Truncation();
        private Layer2Truncation layer2 = new Layer2Truncation();

        @Data
        public static class Layer1Truncation {
            private int userAgent = 150;
            private int payload = 200;
            private int ragDocument = 180;
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
        private int vectorSearchLimit = 3;
        private String defaultBudgetProfile = "CORTEX_L1_INTERACTIVE_STRICT";

        @Data
        public static class Prompt {

            private int maxSimilarEvents = 2;

            private int maxRagDocuments = 3;

            private boolean includeEventId = false;

            private boolean includeRawTimestamp = false;

            private boolean includeRawSessionId = false;

            private boolean includeFullUserAgent = false;
        }

        @Data
        public static class Timeout {

            private long totalMs = 5000;

            private long llmMs = 3200;

            private long ragMs = 900;
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

        private long timeoutMs = 7000;
        private boolean enableSoar = false;
        private int ragTopK = 5;
        private String defaultBudgetProfile = "CORTEX_L2_EXPERT_STRICT";

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

