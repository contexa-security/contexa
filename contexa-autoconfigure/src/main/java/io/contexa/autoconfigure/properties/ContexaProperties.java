package io.contexa.autoconfigure.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;


@Data
@ConfigurationProperties(prefix = "contexa")
public class ContexaProperties {

    
    private boolean enabled = true;

    private Enterprise enterprise = new Enterprise();

    
    private Hcad hcad = new Hcad();

    
    private Llm llm = new Llm();

    
    private Rag rag = new Rag();

    
    private Autonomous autonomous = new Autonomous();

    
    private Simulation simulation = new Simulation();

    
    private Feedback feedback = new Feedback();

    
    private Infrastructure infrastructure = new Infrastructure();

    @NestedConfigurationProperty
    private Saas saas = new Saas();

    public Saas getSaas() {
        return saas;
    }

    
    
    

    
    @Data
    public static class Hcad {
        
        private boolean enabled = true;


        private Similarity similarity = new Similarity();

        
        private Baseline baseline = new Baseline();

        @Data
        public static class Similarity {
            
            private double hotPathThreshold = 0.7;

            
            private double minimalThreshold = 0.8;

            
            private double lowThreshold = 0.6;

            
            private double mediumThreshold = 0.4;

            
            private double highThreshold = 0.2;
        }

        @Data
        public static class Baseline {
            
            private int minSamples = 10;

            
            private int cacheTtl = 3600;

            
            private boolean autoLearning = true;
        }
    }

    
    @Data
    public static class Llm {
        
        private boolean enabled = true;
        private boolean tieredEnabled = true;
        private boolean advisorEnabled = true;
        private boolean pipelineEnabled = true;
        private String chatModelPriority = "ollama,anthropic,openai";
        private String embeddingModelPriority = "ollama,openai";
    }

    
    @Data
    public static class Rag {
        
        private boolean enabled = true;

        
        private VectorStore vectorStore = new VectorStore();

        @Data
        public static class VectorStore {
            
            private String type = "pgvector";

            
            private int defaultTopK = 5;

            
            private double defaultSimilarityThreshold = 0.7;
        }
    }

    
    @Data
    public static class Autonomous {
        
        private boolean enabled = true;

        
        private String strategyMode = "dynamic";

        
        private long eventTimeout = 30000;
    }

    
    @Data
    public static class Simulation {
        
        private boolean enabled = false;

        
        private SimulationData data = new SimulationData();

        @Data
        public static class SimulationData {
            
            private boolean enabled = false;

            
            private boolean clearExisting = false;
        }
    }

    
    @Data
    public static class Feedback {
        
        private boolean enabled = true;

        
        private long collectionInterval = 60000;
    }

    @Data
    public static class Enterprise {
        private boolean enabled = false;
    }

    public enum InfrastructureMode {
        STANDALONE,
        DISTRIBUTED
    }

    @Data
    public static class Infrastructure {

        private InfrastructureMode mode = InfrastructureMode.STANDALONE;

        private Redis redis = new Redis();


        private Kafka kafka = new Kafka();


        private Observability observability = new Observability();

        @Data
        public static class Redis {
            
            private boolean enabled = true;

            
            private boolean redissonEnabled = false;
        }

        @Data
        public static class Kafka {
            
            private boolean enabled = true;
        }

        @Data
        public static class Observability {
            
            private boolean enabled = true;

            
            private boolean openTelemetryEnabled = true;
        }
    }

    @Data
    public static class Saas {

        public static final String XAI_DECISION_INGEST_SCOPE = "saas.xai.decision.ingest";
        public static final String FEEDBACK_INGEST_SCOPE = "saas.feedback.ingest";
        public static final String BASELINE_SIGNAL_INGEST_SCOPE = "saas.baseline.ingest";
        public static final String BASELINE_SEED_READ_SCOPE = "saas.baseline-seed.read";
        public static final String THREAT_INTELLIGENCE_READ_SCOPE = "saas.threat-intelligence.read";
        public static final String THREAT_OUTCOME_INGEST_SCOPE = "saas.threat-outcome.ingest";
        public static final String THREAT_KNOWLEDGE_READ_SCOPE = "saas.threat-knowledge.read";
        public static final String PERFORMANCE_TELEMETRY_INGEST_SCOPE = "saas.telemetry.ingest";
        public static final String PROMPT_CONTEXT_AUDIT_INGEST_SCOPE = "saas.prompt-context-audit.ingest";

        private boolean enabled = false;

        private String endpoint;

        private boolean includeReasoning = false;

        private boolean includeRawAnalysisData = false;

        private int outboxBatchSize = 50;

        private int maxRetryAttempts = 10;

        private long retryInitialBackoffMs = 1_000L;

        private long retryMaxBackoffMs = 60_000L;

        private long dispatchIntervalMs = 30_000L;

        private String pseudonymizationSecret;

        private String globalCorrelationSecret;

        @NestedConfigurationProperty
        private Oauth2 oauth2 = new Oauth2();

        @NestedConfigurationProperty
        private DecisionFeedback decisionFeedback = new DecisionFeedback();

        @NestedConfigurationProperty
        private BaselineSignal baselineSignal = new BaselineSignal();

        @NestedConfigurationProperty
        private ThreatIntelligence threatIntelligence = new ThreatIntelligence();

        @NestedConfigurationProperty
        private ThreatOutcome threatOutcome = new ThreatOutcome();

        @NestedConfigurationProperty
        private ThreatKnowledge threatKnowledge = new ThreatKnowledge();

        @NestedConfigurationProperty
        private PerformanceTelemetry performanceTelemetry = new PerformanceTelemetry();

        @NestedConfigurationProperty
        private PromptContextAudit promptContextAudit = new PromptContextAudit();

        public boolean isEnabled() {
            return enabled;
        }

        public String getEndpoint() {
            return endpoint;
        }

        public boolean isIncludeReasoning() {
            return includeReasoning;
        }

        public boolean isIncludeRawAnalysisData() {
            return includeRawAnalysisData;
        }

        public int getOutboxBatchSize() {
            return outboxBatchSize;
        }

        public int getMaxRetryAttempts() {
            return maxRetryAttempts;
        }

        public long getRetryInitialBackoffMs() {
            return retryInitialBackoffMs;
        }

        public long getRetryMaxBackoffMs() {
            return retryMaxBackoffMs;
        }

        public long getDispatchIntervalMs() {
            return dispatchIntervalMs;
        }

        public String getPseudonymizationSecret() {
            return pseudonymizationSecret;
        }

        public String getGlobalCorrelationSecret() {
            return globalCorrelationSecret;
        }

        public Oauth2 getOauth2() {
            return oauth2;
        }

        public DecisionFeedback getDecisionFeedback() {
            return decisionFeedback;
        }

        public BaselineSignal getBaselineSignal() {
            return baselineSignal;
        }

        public ThreatIntelligence getThreatIntelligence() {
            return threatIntelligence;
        }

        public ThreatOutcome getThreatOutcome() {
            return threatOutcome;
        }

        public ThreatKnowledge getThreatKnowledge() {
            return threatKnowledge;
        }

        public PerformanceTelemetry getPerformanceTelemetry() {
            return performanceTelemetry;
        }

        public PromptContextAudit getPromptContextAudit() {
            return promptContextAudit;
        }

        public void validate() {
            if (!enabled) {
                return;
            }
            if (endpoint == null || endpoint.isBlank()) {
                throw new IllegalStateException("contexa.saas.endpoint must be configured when SaaS forwarding is enabled");
            }
            if (pseudonymizationSecret == null || pseudonymizationSecret.isBlank()) {
                throw new IllegalStateException("contexa.saas.pseudonymization-secret must be configured when SaaS forwarding is enabled");
            }
            if (globalCorrelationSecret == null || globalCorrelationSecret.isBlank()) {
                throw new IllegalStateException("contexa.saas.global-correlation-secret must be configured when SaaS forwarding is enabled");
            }
            if (!oauth2.enabled) {
                throw new IllegalStateException("contexa.saas.oauth2.enabled must be true when SaaS forwarding is enabled");
            }
            oauth2.validate();
            requireScope(XAI_DECISION_INGEST_SCOPE, "contexa.saas.oauth2.scope must include saas.xai.decision.ingest");
            decisionFeedback.validate(oauth2.scope);
            baselineSignal.validate(oauth2.scope);
            threatIntelligence.validate(oauth2.scope);
            threatOutcome.validate(oauth2.scope);
            threatKnowledge.validate(oauth2.scope);
            performanceTelemetry.validate(oauth2.scope);
            promptContextAudit.validate(oauth2.scope);
        }

        private void requireScope(String requiredScope, String message) {
            if (!hasScope(oauth2.scope, requiredScope)) {
                throw new IllegalStateException(message);
            }
        }

        private boolean hasScope(String configuredScopes, String requiredScope) {
            if (configuredScopes == null || configuredScopes.isBlank()) {
                return false;
            }
            for (String scope : configuredScopes.trim().split("[,\\s]+")) {
                if (requiredScope.equals(scope)) {
                    return true;
                }
            }
            return false;
        }

        @Data
        public static class Oauth2 {

            private boolean enabled = true;

            private String registrationId = "contexa-saas-client";

            private String tokenUri;

            private String clientId;

            private String clientSecret;

            private String scope = "saas.xai.decision.ingest";

            private int expirySkewSeconds = 30;

            public boolean isEnabled() {
                return enabled;
            }

            public String getRegistrationId() {
                return registrationId;
            }

            public String getTokenUri() {
                return tokenUri;
            }

            public String getClientId() {
                return clientId;
            }

            public String getClientSecret() {
                return clientSecret;
            }

            public String getScope() {
                return scope;
            }

            public int getExpirySkewSeconds() {
                return expirySkewSeconds;
            }

            public void validate() {
                if (!enabled) {
                    return;
                }
                if (registrationId == null || registrationId.isBlank()) {
                    throw new IllegalStateException("contexa.saas.oauth2.registration-id must be configured");
                }
                if (tokenUri == null || tokenUri.isBlank()) {
                    throw new IllegalStateException("contexa.saas.oauth2.token-uri must be configured");
                }
                if (clientId == null || clientId.isBlank()) {
                    throw new IllegalStateException("contexa.saas.oauth2.client-id must be configured");
                }
                if (clientSecret == null || clientSecret.isBlank()) {
                    throw new IllegalStateException("contexa.saas.oauth2.client-secret must be configured");
                }
                if (scope == null || scope.isBlank()) {
                    throw new IllegalStateException("contexa.saas.oauth2.scope must be configured");
                }
            }
        }

        @Data
        public static class DecisionFeedback {

            private boolean enabled = false;

            private String endpointPath = "/api/saas/runtime/ai-tuning/feedback-ingestions";

            public boolean isEnabled() {
                return enabled;
            }

            public String getEndpointPath() {
                return endpointPath;
            }

            public void validate(String oauthScopes) {
                if (!enabled) {
                    return;
                }
                if (endpointPath == null || endpointPath.isBlank()) {
                    throw new IllegalStateException("contexa.saas.decision-feedback.endpoint-path must be configured when decision feedback forwarding is enabled");
                }
                boolean scopePresent = false;
                if (oauthScopes != null && !oauthScopes.isBlank()) {
                    for (String scope : oauthScopes.trim().split("[,\\s]+")) {
                        if (FEEDBACK_INGEST_SCOPE.equals(scope)) {
                            scopePresent = true;
                            break;
                        }
                    }
                }
                if (!scopePresent) {
                    throw new IllegalStateException("contexa.saas.oauth2.scope must include saas.feedback.ingest when decision feedback forwarding is enabled");
                }
            }
        }

        @Data
        public static class BaselineSignal {

            private boolean enabled = false;

            private String endpointPath = "/api/saas/runtime/ai-tuning/baseline-signals";

            private String seedEndpointPath = "/api/saas/runtime/ai-tuning/baseline-seed";

            private long publishIntervalMs = 604_800_000L;

            private long initialDelayMs = 300_000L;

            private long seedPullIntervalMs = 3_600_000L;

            private long seedInitialDelayMs = 120_000L;

            private int seedCacheTtlMinutes = 180;

            private int minimumOrganizationBaselineCount = 3;

            private int minimumUserBaselineCount = 25;

            private int hourBucketLimit = 8;

            private int dayBucketLimit = 7;

            private int operatingSystemLimit = 6;

            private String industryCategory = "GENERAL";

            public boolean isEnabled() {
                return enabled;
            }

            public String getEndpointPath() {
                return endpointPath;
            }

            public String getSeedEndpointPath() {
                return seedEndpointPath;
            }

            public long getPublishIntervalMs() {
                return publishIntervalMs;
            }

            public long getInitialDelayMs() {
                return initialDelayMs;
            }

            public long getSeedPullIntervalMs() {
                return seedPullIntervalMs;
            }

            public long getSeedInitialDelayMs() {
                return seedInitialDelayMs;
            }

            public int getSeedCacheTtlMinutes() {
                return seedCacheTtlMinutes;
            }

            public int getMinimumOrganizationBaselineCount() {
                return minimumOrganizationBaselineCount;
            }

            public int getMinimumUserBaselineCount() {
                return minimumUserBaselineCount;
            }

            public int getHourBucketLimit() {
                return hourBucketLimit;
            }

            public int getDayBucketLimit() {
                return dayBucketLimit;
            }

            public int getOperatingSystemLimit() {
                return operatingSystemLimit;
            }

            public String getIndustryCategory() {
                return industryCategory;
            }

            public void validate(String oauthScopes) {
                if (!enabled) {
                    return;
                }
                if (endpointPath == null || endpointPath.isBlank()) {
                    throw new IllegalStateException("contexa.saas.baseline-signal.endpoint-path must be configured when baseline signal sharing is enabled");
                }
                if (seedEndpointPath == null || seedEndpointPath.isBlank()) {
                    throw new IllegalStateException("contexa.saas.baseline-signal.seed-endpoint-path must be configured when baseline seed pull is enabled");
                }
                if (publishIntervalMs <= 0L) {
                    throw new IllegalStateException("contexa.saas.baseline-signal.publish-interval-ms must be greater than zero");
                }
                if (initialDelayMs < 0L) {
                    throw new IllegalStateException("contexa.saas.baseline-signal.initial-delay-ms must not be negative");
                }
                if (seedPullIntervalMs <= 0L) {
                    throw new IllegalStateException("contexa.saas.baseline-signal.seed-pull-interval-ms must be greater than zero");
                }
                if (seedInitialDelayMs < 0L) {
                    throw new IllegalStateException("contexa.saas.baseline-signal.seed-initial-delay-ms must not be negative");
                }
                if (seedCacheTtlMinutes <= 0) {
                    throw new IllegalStateException("contexa.saas.baseline-signal.seed-cache-ttl-minutes must be greater than zero");
                }
                if (minimumOrganizationBaselineCount <= 0) {
                    throw new IllegalStateException("contexa.saas.baseline-signal.minimum-organization-baseline-count must be greater than zero");
                }
                if (minimumUserBaselineCount <= 0) {
                    throw new IllegalStateException("contexa.saas.baseline-signal.minimum-user-baseline-count must be greater than zero");
                }
                if (hourBucketLimit <= 0) {
                    throw new IllegalStateException("contexa.saas.baseline-signal.hour-bucket-limit must be greater than zero");
                }
                if (dayBucketLimit <= 0) {
                    throw new IllegalStateException("contexa.saas.baseline-signal.day-bucket-limit must be greater than zero");
                }
                if (operatingSystemLimit <= 0) {
                    throw new IllegalStateException("contexa.saas.baseline-signal.operating-system-limit must be greater than zero");
                }
                if (industryCategory == null || industryCategory.isBlank()) {
                    throw new IllegalStateException("contexa.saas.baseline-signal.industry-category must not be empty");
                }
                boolean ingestScopePresent = false;
                boolean seedReadScopePresent = false;
                if (oauthScopes != null && !oauthScopes.isBlank()) {
                    for (String scope : oauthScopes.trim().split("[,\\s]+")) {
                        if (BASELINE_SIGNAL_INGEST_SCOPE.equals(scope)) {
                            ingestScopePresent = true;
                        }
                        if (BASELINE_SEED_READ_SCOPE.equals(scope)) {
                            seedReadScopePresent = true;
                        }
                    }
                }
                if (!ingestScopePresent) {
                    throw new IllegalStateException("contexa.saas.oauth2.scope must include saas.baseline.ingest when baseline signal sharing is enabled");
                }
                if (!seedReadScopePresent) {
                    throw new IllegalStateException("contexa.saas.oauth2.scope must include saas.baseline-seed.read when baseline signal sharing is enabled");
                }
            }
        }

        @Data
        public static class ThreatIntelligence {

            private boolean enabled = false;

            private String endpointPath = "/api/saas/runtime/ai-tuning/threat-signals";

            private long pullIntervalMs = 3_600_000L;

            private long initialDelayMs = 0L;

            private int signalLimit = 5;

            private int promptLimit = 3;

            private int cacheTtlMinutes = 90;

            public boolean isEnabled() {
                return enabled;
            }

            public String getEndpointPath() {
                return endpointPath;
            }

            public long getPullIntervalMs() {
                return pullIntervalMs;
            }

            public long getInitialDelayMs() {
                return initialDelayMs;
            }

            public int getSignalLimit() {
                return signalLimit;
            }

            public int getPromptLimit() {
                return promptLimit;
            }

            public int getCacheTtlMinutes() {
                return cacheTtlMinutes;
            }

            public void validate(String oauthScopes) {
                if (!enabled) {
                    return;
                }
                if (endpointPath == null || endpointPath.isBlank()) {
                    throw new IllegalStateException("contexa.saas.threat-intelligence.endpoint-path must be configured when threat intelligence pull is enabled");
                }
                if (pullIntervalMs <= 0L) {
                    throw new IllegalStateException("contexa.saas.threat-intelligence.pull-interval-ms must be greater than zero");
                }
                if (initialDelayMs < 0L) {
                    throw new IllegalStateException("contexa.saas.threat-intelligence.initial-delay-ms must not be negative");
                }
                if (signalLimit <= 0) {
                    throw new IllegalStateException("contexa.saas.threat-intelligence.signal-limit must be greater than zero");
                }
                if (promptLimit <= 0) {
                    throw new IllegalStateException("contexa.saas.threat-intelligence.prompt-limit must be greater than zero");
                }
                if (cacheTtlMinutes <= 0) {
                    throw new IllegalStateException("contexa.saas.threat-intelligence.cache-ttl-minutes must be greater than zero");
                }
                boolean scopePresent = false;
                if (oauthScopes != null && !oauthScopes.isBlank()) {
                    for (String scope : oauthScopes.trim().split("[,\\s]+")) {
                        if (THREAT_INTELLIGENCE_READ_SCOPE.equals(scope)) {
                            scopePresent = true;
                            break;
                        }
                    }
                }
                if (!scopePresent) {
                    throw new IllegalStateException("contexa.saas.oauth2.scope must include saas.threat-intelligence.read when threat intelligence pull is enabled");
                }
            }
        }

        @Data
        public static class ThreatOutcome {

            private boolean enabled = false;

            private String endpointPath = "/api/saas/runtime/ai-tuning/threat-outcomes";

            public boolean isEnabled() {
                return enabled;
            }

            public String getEndpointPath() {
                return endpointPath;
            }

            public void validate(String oauthScopes) {
                if (!enabled) {
                    return;
                }
                if (endpointPath == null || endpointPath.isBlank()) {
                    throw new IllegalStateException("contexa.saas.threat-outcome.endpoint-path must be configured when threat outcome forwarding is enabled");
                }
                boolean scopePresent = false;
                if (oauthScopes != null && !oauthScopes.isBlank()) {
                    for (String scope : oauthScopes.trim().split("[,\\s]+")) {
                        if (THREAT_OUTCOME_INGEST_SCOPE.equals(scope)) {
                            scopePresent = true;
                            break;
                        }
                    }
                }
                if (!scopePresent) {
                    throw new IllegalStateException("contexa.saas.oauth2.scope must include saas.threat-outcome.ingest when threat outcome forwarding is enabled");
                }
            }
        }

        @Data
        public static class ThreatKnowledge {

            private boolean enabled = false;

            private String endpointPath = "/api/saas/runtime/ai-tuning/threat-knowledge-pack";

            private String runtimePolicyEndpointPath = "/api/saas/runtime/ai-tuning/threat-runtime-policy";

            private long pullIntervalMs = 3_600_000L;

            private long initialDelayMs = 0L;

            private int caseLimit = 12;

            private int promptLimit = 3;

            private int cacheTtlMinutes = 90;

            public boolean isEnabled() {
                return enabled;
            }

            public String getEndpointPath() {
                return endpointPath;
            }

            public String getRuntimePolicyEndpointPath() {
                return runtimePolicyEndpointPath;
            }

            public long getPullIntervalMs() {
                return pullIntervalMs;
            }

            public long getInitialDelayMs() {
                return initialDelayMs;
            }

            public int getCaseLimit() {
                return caseLimit;
            }

            public int getPromptLimit() {
                return promptLimit;
            }

            public int getCacheTtlMinutes() {
                return cacheTtlMinutes;
            }

            public void validate(String oauthScopes) {
                if (!enabled) {
                    return;
                }
                if (endpointPath == null || endpointPath.isBlank()) {
                    throw new IllegalStateException("contexa.saas.threat-knowledge.endpoint-path must be configured when threat knowledge pull is enabled");
                }
                if (runtimePolicyEndpointPath == null || runtimePolicyEndpointPath.isBlank()) {
                    throw new IllegalStateException("contexa.saas.threat-knowledge.runtime-policy-endpoint-path must be configured when threat knowledge pull is enabled");
                }
                if (pullIntervalMs <= 0L) {
                    throw new IllegalStateException("contexa.saas.threat-knowledge.pull-interval-ms must be greater than zero");
                }
                if (initialDelayMs < 0L) {
                    throw new IllegalStateException("contexa.saas.threat-knowledge.initial-delay-ms must not be negative");
                }
                if (caseLimit <= 0) {
                    throw new IllegalStateException("contexa.saas.threat-knowledge.case-limit must be greater than zero");
                }
                if (promptLimit <= 0) {
                    throw new IllegalStateException("contexa.saas.threat-knowledge.prompt-limit must be greater than zero");
                }
                if (cacheTtlMinutes <= 0) {
                    throw new IllegalStateException("contexa.saas.threat-knowledge.cache-ttl-minutes must be greater than zero");
                }
                boolean scopePresent = false;
                if (oauthScopes != null && !oauthScopes.isBlank()) {
                    for (String scope : oauthScopes.trim().split("[,\\s]+")) {
                        if (THREAT_KNOWLEDGE_READ_SCOPE.equals(scope)) {
                            scopePresent = true;
                            break;
                        }
                    }
                }
                if (!scopePresent) {
                    throw new IllegalStateException("contexa.saas.oauth2.scope must include saas.threat-knowledge.read when threat knowledge pull is enabled");
                }
            }
        }

        @Data
        public static class PerformanceTelemetry {

            private boolean enabled = false;

            private String endpointPath = "/api/saas/runtime/ai-tuning/performance-telemetry";

            private long publishIntervalMs = 3_600_000L;

            private long initialDelayMs = 60_000L;

            public boolean isEnabled() {
                return enabled;
            }

            public String getEndpointPath() {
                return endpointPath;
            }

            public long getPublishIntervalMs() {
                return publishIntervalMs;
            }

            public long getInitialDelayMs() {
                return initialDelayMs;
            }

            public void validate(String oauthScopes) {
                if (!enabled) {
                    return;
                }
                if (endpointPath == null || endpointPath.isBlank()) {
                    throw new IllegalStateException("contexa.saas.performance-telemetry.endpoint-path must be configured when performance telemetry forwarding is enabled");
                }
                if (publishIntervalMs <= 0L) {
                    throw new IllegalStateException("contexa.saas.performance-telemetry.publish-interval-ms must be greater than zero");
                }
                if (initialDelayMs < 0L) {
                    throw new IllegalStateException("contexa.saas.performance-telemetry.initial-delay-ms must not be negative");
                }
                boolean scopePresent = false;
                if (oauthScopes != null && !oauthScopes.isBlank()) {
                    for (String scope : oauthScopes.trim().split("[,\\s]+")) {
                        if (PERFORMANCE_TELEMETRY_INGEST_SCOPE.equals(scope)) {
                            scopePresent = true;
                            break;
                        }
                    }
                }
                if (!scopePresent) {
                    throw new IllegalStateException("contexa.saas.oauth2.scope must include saas.telemetry.ingest when performance telemetry forwarding is enabled");
                }
            }
        }

        @Data
        public static class PromptContextAudit {

            private boolean enabled = false;

            private String endpointPath = "/api/saas/runtime/prompt-context-audits";

            public boolean isEnabled() {
                return enabled;
            }

            public String getEndpointPath() {
                return endpointPath;
            }

            public void validate(String oauthScopes) {
                if (!enabled) {
                    return;
                }
                if (endpointPath == null || endpointPath.isBlank()) {
                    throw new IllegalStateException("contexa.saas.prompt-context-audit.endpoint-path must be configured when prompt context audit forwarding is enabled");
                }
                boolean scopePresent = false;
                if (oauthScopes != null && !oauthScopes.isBlank()) {
                    for (String scope : oauthScopes.trim().split("[,\\s]+")) {
                        if (PROMPT_CONTEXT_AUDIT_INGEST_SCOPE.equals(scope)) {
                            scopePresent = true;
                            break;
                        }
                    }
                }
                if (!scopePresent) {
                    throw new IllegalStateException("contexa.saas.oauth2.scope must include saas.prompt-context-audit.ingest when prompt context audit forwarding is enabled");
                }
            }
        }
    }
}
