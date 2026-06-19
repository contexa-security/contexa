/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.properties;

import io.contexa.contexacore.hcad.trigger.HcadPreTriggerMode;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.ArrayList;
import java.util.List;

@Data
@ConfigurationProperties(prefix = "contexa.hcad")
public class HcadProperties {

    private boolean enabled = true;
    private int filterOrder = 100;

    @NestedConfigurationProperty
    private FilterSettings filter = new FilterSettings();

    @NestedConfigurationProperty
    private ResourceSettings resource = new ResourceSettings();

    @NestedConfigurationProperty
    private AnalysisSettings analysis = new AnalysisSettings();

    @NestedConfigurationProperty
    private ThresholdSettings threshold = new ThresholdSettings();

    @NestedConfigurationProperty
    private CacheSettings cache = new CacheSettings();

    @NestedConfigurationProperty
    private BaselineSettings baseline = new BaselineSettings();

    @NestedConfigurationProperty
    private FeedbackSettings feedback = new FeedbackSettings();

    @NestedConfigurationProperty
    private OrchestratorSettings orchestrator = new OrchestratorSettings();

    @NestedConfigurationProperty
    private VectorSettings vector = new VectorSettings();

    @NestedConfigurationProperty
    private SessionSettings session = new SessionSettings();

    @NestedConfigurationProperty
    private SignalSettings signal = new SignalSettings();

    @NestedConfigurationProperty
    private SamplingSettings sampling = new SamplingSettings();

    @NestedConfigurationProperty
    private AdaptiveSettings adaptive = new AdaptiveSettings();

    @NestedConfigurationProperty
    private SimilaritySettings similarity = new SimilaritySettings();

    @NestedConfigurationProperty
    private RedisSettings redis = new RedisSettings();

    @NestedConfigurationProperty
    private GeoIpSettings geoip = new GeoIpSettings();

    @NestedConfigurationProperty
    private PreTriggerSettings preTrigger = new PreTriggerSettings();

    @Data
    public static class ThresholdSettings {
        private double base = 0.7;
        private double min = 0.3;
        private double max = 0.95;
        private double adjustmentRate = 0.01;
        private double sensitivity = 1.0;
        private double warn = 0.7;
    }

    @Data
    public static class CacheSettings {
        private int maxSize = 100000;
        private long ttlMs = 300000L;
        private boolean clearOnStartup = false;

        @NestedConfigurationProperty
        private LocalCacheSettings local = new LocalCacheSettings();

        @Data
        public static class LocalCacheSettings {
            private int ttlMinutes = 10;
        }
    }

    @Data
    public static class AnalysisSettings {
        private long maxAgeMs = 3600000L;
    }

    @Data
    public static class BaselineSettings {
        private double minConfidence = 0.3;
        private double updateAlpha = 0.1;

        @NestedConfigurationProperty
        private LearningSettings learning = new LearningSettings();

        @NestedConfigurationProperty
        private BootstrapSettings bootstrap = new BootstrapSettings();

        @Data
        public static class LearningSettings {
            private double alpha = 0.1;
            private boolean enabled = true;
        }

        @NestedConfigurationProperty
        private StatisticalSettings statistical = new StatisticalSettings();

        @NestedConfigurationProperty
        private RedisSettings redis = new RedisSettings();

        @Data
        public static class BootstrapSettings {
            private boolean enabled = true;
            private int initialSamples = 10;
            private double maxAnomalyScore = 0.85;
        }

        @Data
        public static class StatisticalSettings {
            private boolean enabled = true;
            private int minSamples = 20;
            private int updateInterval = 10;
            private double zScoreThreshold = 3.0;
        }

        @Data
        public static class RedisSettings {
            private int ttlDays = 30;
        }
    }

    @Data
    public static class FeedbackSettings {
        private double learningRate = 0.1;
        private double retrainThreshold = 0.7;
        private int windowSize = 1000;

        @NestedConfigurationProperty
        private BaselineUpdateSettings baseline = new BaselineUpdateSettings();

        @Data
        public static class BaselineUpdateSettings {
            private double updateThreshold = 0.95;
        }
    }

    @Data
    public static class OrchestratorSettings {
        private boolean enabled = true;
        private int feedbackInterval = 300;
        private int syncBatchSize = 50;
        private boolean performanceTracking = true;
    }

    @Data
    public static class VectorSettings {
        private int embeddingDimension = 384;
        private int cacheTtlHours = 24;
        private int maxCachedEmbeddings = 1000;
        private double similarityThreshold = 0.85;
        private boolean scenarioDetectionEnabled = true;
    }

    @Data
    public static class SessionSettings {
        private String cookieName = "JSESSIONID";
        private String headerName = "X-Session-Id";
    }

    @Data
    public static class SignalSettings {
        private double chiSquareThreshold = 14.07;
        private int historySize = 100;

        @NestedConfigurationProperty
        private CovarianceSettings covariance = new CovarianceSettings();

        @NestedConfigurationProperty
        private GeoipSettings geoip = new GeoipSettings();

        @NestedConfigurationProperty
        private TimingSettings timing = new TimingSettings();

        @Data
        public static class CovarianceSettings {
            private int minSamples = 30;
        }

        @Data
        public static class GeoipSettings {
            private String provider = "api";
            private String apiUrl = "https://ipapi.co/{ip}/json/";
        }

        @Data
        public static class TimingSettings {
            private int bucketCount = 7;

            @NestedConfigurationProperty
            private IntervalSettings interval = new IntervalSettings();

            @Data
            public static class IntervalSettings {
                private int historySize = 100;
            }
        }
    }

    @Data
    public static class SamplingSettings {
        @NestedConfigurationProperty
        private RandomSettings random = new RandomSettings();

        @NestedConfigurationProperty
        private CompositeSettings composite = new CompositeSettings();

        @Data
        public static class RandomSettings {
            private double floor = 0.01;
            private double ceiling = 0.03;
        }

        @Data
        public static class CompositeSettings {
            @NestedConfigurationProperty
            private IdentifierSettings identifier = new IdentifierSettings();

            @Data
            public static class IdentifierSettings {
                private boolean enabled = true;
            }
        }
    }

    @Data
    public static class AdaptiveSettings {
        private double adjustmentRate = 0.1;

        @NestedConfigurationProperty
        private CusumSettings cusum = new CusumSettings();

        @NestedConfigurationProperty
        private BaselineSettings baseline = new BaselineSettings();

        @NestedConfigurationProperty
        private MinSettings min = new MinSettings();

        @Data
        public static class CusumSettings {
            private double threshold = 5.0;
            private double slack = 0.5;
        }

        @Data
        public static class BaselineSettings {
            private int window = 100;
        }

        @Data
        public static class MinSettings {
            @NestedConfigurationProperty
            private TrustSettings trust = new TrustSettings();

            @Data
            public static class TrustSettings {
                private double score = 0.7;
            }
        }
    }

    @Data
    public static class ResourceSettings {
        private List<String> sensitivePatterns = new ArrayList<>();
    }

    @Data
    public static class FilterSettings {
        private List<String> excludedPatterns = new ArrayList<>();
    }

    @Data
    public static class SimilaritySettings {
        private double hotPathThreshold = 0.7;
    }

    @Data
    public static class RedisSettings {
        private String keyPrefix = "hcad:baseline:v2:";
    }

    @Data
    public static class GeoIpSettings {
        private boolean enabled = false;
        private String dbPath = "data/GeoLite2-City.mmdb";
    }

    @Data
    public static class PreTriggerSettings {
        private boolean enabled = true;
        private HcadPreTriggerMode mode = HcadPreTriggerMode.SHADOW;
        private int cooldownSeconds = 15;
        private int inFlightTtlSeconds = 15;
        private int negativeCacheSeconds = 3;
        private int redlineScore = 70;
        private int highRiskScore = 50;
        private int mediumRiskScore = 30;
        private double lowBaselineConfidenceThreshold = 0.35;
        private int failedLoginBurstThreshold = 3;
        private int requestBurstThreshold = 12;
        private long rapidRequestIntervalMs = 1000L;
        private long freshMfaMaxAgeSeconds = 300L;
        private long staleAuthenticationMaxAgeSeconds = 3600L;
        private int permissionChangeObservationLimit = 5;
        private List<String> lowAuthenticationAssuranceValues = new ArrayList<>(List.of(
                "low",
                "loa1",
                "basic",
                "password"
        ));

        @NestedConfigurationProperty
        private LlmRateLimitSettings llmRateLimit = new LlmRateLimitSettings();

        @NestedConfigurationProperty
        private QualificationSettings qualification = new QualificationSettings();

        public HcadPreTriggerMode effectiveMode() {
            return enabled ? HcadPreTriggerMode.from(mode) : HcadPreTriggerMode.DISABLED;
        }

        public boolean shouldEvaluate() {
            return effectiveMode().evaluatesRequest();
        }

        public boolean shouldPublishLlmEvent() {
            return effectiveMode().publishesLlmEvent();
        }

        @Data
        public static class LlmRateLimitSettings {
            private boolean enabled = true;
            private int maxTriggersPerWindow = 120;
            private int windowSeconds = 60;
            private String scope = "GLOBAL";
        }

        @Data
        public static class QualificationSettings {
            private double shadowMinPrecision = 0.80;
            private double limitedEnforceMinPrecision = 0.90;
            private double defaultEnforceMinPrecision = 0.95;
            private int minimumSampleSize = 100;
            private double estimatedLlmCallCostUsd = 0.0d;
        }
    }
}

