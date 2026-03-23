package io.contexa.contexacore.properties;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class SaasForwardingProperties {

    public static final String XAI_DECISION_INGEST_SCOPE = "saas.xai.decision.ingest";
    public static final String FEEDBACK_INGEST_SCOPE = "saas.feedback.ingest";
    public static final String BASELINE_SIGNAL_INGEST_SCOPE = "saas.baseline.ingest";
    public static final String BASELINE_SEED_READ_SCOPE = "saas.baseline-seed.read";
    public static final String THREAT_INTELLIGENCE_READ_SCOPE = "saas.threat-intelligence.read";
    public static final String THREAT_OUTCOME_INGEST_SCOPE = "saas.threat-outcome.ingest";
    public static final String THREAT_KNOWLEDGE_READ_SCOPE = "saas.threat-knowledge.read";
    public static final String PERFORMANCE_TELEMETRY_INGEST_SCOPE = "saas.telemetry.ingest";
    public static final String PROMPT_CONTEXT_AUDIT_INGEST_SCOPE = "saas.prompt-context-audit.ingest";

    private final boolean enabled;
    private final String endpoint;
    private final boolean includeReasoning;
    private final boolean includeRawAnalysisData;
    private final int outboxBatchSize;
    private final int maxRetryAttempts;
    private final long retryInitialBackoffMs;
    private final long retryMaxBackoffMs;
    private final long dispatchIntervalMs;
    private final String pseudonymizationSecret;
    private final String globalCorrelationSecret;
    private final OAuth2 oauth2;
    private final DecisionFeedback decisionFeedback;
    private final BaselineSignal baselineSignal;
    private final ThreatIntelligence threatIntelligence;
    private final ThreatOutcome threatOutcome;
    private final ThreatKnowledge threatKnowledge;
    private final PerformanceTelemetry performanceTelemetry;
    private final PromptContextAudit promptContextAudit;

    public void validate() {
        if (!enabled) {
            return;
        }
        if (endpoint == null || endpoint.isBlank()) {
            throw new IllegalStateException("SaaS forwarding endpoint must be configured");
        }
        if (pseudonymizationSecret == null || pseudonymizationSecret.isBlank()) {
            throw new IllegalStateException("SaaS forwarding pseudonymization secret must be configured");
        }
        if (globalCorrelationSecret == null || globalCorrelationSecret.isBlank()) {
            throw new IllegalStateException("SaaS forwarding global correlation secret must be configured");
        }
        if (oauth2 == null) {
            throw new IllegalStateException("SaaS forwarding OAuth2 configuration must be configured");
        }
        oauth2.validate();
        requireScope(XAI_DECISION_INGEST_SCOPE, "SaaS forwarding OAuth2 scope must include saas.xai.decision.ingest");
        if (decisionFeedback != null) {
            decisionFeedback.validate(oauth2.scope);
        }
        if (baselineSignal != null) {
            baselineSignal.validate(oauth2.scope);
        }
        if (threatIntelligence != null) {
            threatIntelligence.validate(oauth2.scope);
        }
        if (threatOutcome != null) {
            threatOutcome.validate(oauth2.scope);
        }
        if (threatKnowledge != null) {
            threatKnowledge.validate(oauth2.scope);
        }
        if (performanceTelemetry != null) {
            performanceTelemetry.validate(oauth2.scope);
        }
        if (promptContextAudit != null) {
            promptContextAudit.validate(oauth2.scope);
        }
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

    @Getter
    @Builder
    public static class OAuth2 {

        private final boolean enabled;
        private final String registrationId;
        private final String tokenUri;
        private final String clientId;
        private final String clientSecret;
        private final String scope;
        private final int expirySkewSeconds;

        public void validate() {
            if (!enabled) {
                throw new IllegalStateException("SaaS forwarding OAuth2 client must be enabled");
            }
            if (registrationId == null || registrationId.isBlank()) {
                throw new IllegalStateException("SaaS forwarding OAuth2 registrationId must be configured");
            }
            if (tokenUri == null || tokenUri.isBlank()) {
                throw new IllegalStateException("SaaS forwarding OAuth2 tokenUri must be configured");
            }
            if (clientId == null || clientId.isBlank()) {
                throw new IllegalStateException("SaaS forwarding OAuth2 clientId must be configured");
            }
            if (clientSecret == null || clientSecret.isBlank()) {
                throw new IllegalStateException("SaaS forwarding OAuth2 clientSecret must be configured");
            }
            if (scope == null || scope.isBlank()) {
                throw new IllegalStateException("SaaS forwarding OAuth2 scope must be configured");
            }
        }
    }

    @Getter
    @Builder
    public static class DecisionFeedback {

        private final boolean enabled;
        private final String endpointPath;

        public void validate(String oauthScopes) {
            if (!enabled) {
                return;
            }
            if (endpointPath == null || endpointPath.isBlank()) {
                throw new IllegalStateException("SaaS decision feedback endpointPath must be configured");
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
                throw new IllegalStateException("SaaS forwarding OAuth2 scope must include saas.feedback.ingest when decision feedback forwarding is enabled");
            }
        }
    }

    @Getter
    @Builder
    public static class BaselineSignal {

        private final boolean enabled;
        private final String endpointPath;
        private final String seedEndpointPath;
        private final long publishIntervalMs;
        private final long initialDelayMs;
        private final long seedPullIntervalMs;
        private final long seedInitialDelayMs;
        private final int seedCacheTtlMinutes;
        private final int minimumOrganizationBaselineCount;
        private final int minimumUserBaselineCount;
        private final int hourBucketLimit;
        private final int dayBucketLimit;
        private final int operatingSystemLimit;
        private final String industryCategory;

        public void validate(String oauthScopes) {
            if (!enabled) {
                return;
            }
            if (endpointPath == null || endpointPath.isBlank()) {
                throw new IllegalStateException("SaaS baseline signal endpointPath must be configured");
            }
            if (seedEndpointPath == null || seedEndpointPath.isBlank()) {
                throw new IllegalStateException("SaaS baseline seed endpointPath must be configured");
            }
            if (publishIntervalMs <= 0L) {
                throw new IllegalStateException("SaaS baseline signal publishIntervalMs must be greater than zero");
            }
            if (initialDelayMs < 0L) {
                throw new IllegalStateException("SaaS baseline signal initialDelayMs must not be negative");
            }
            if (seedPullIntervalMs <= 0L) {
                throw new IllegalStateException("SaaS baseline seed pullIntervalMs must be greater than zero");
            }
            if (seedInitialDelayMs < 0L) {
                throw new IllegalStateException("SaaS baseline seed initialDelayMs must not be negative");
            }
            if (seedCacheTtlMinutes <= 0) {
                throw new IllegalStateException("SaaS baseline seed cacheTtlMinutes must be greater than zero");
            }
            if (minimumOrganizationBaselineCount <= 0) {
                throw new IllegalStateException("SaaS baseline signal minimumOrganizationBaselineCount must be greater than zero");
            }
            if (minimumUserBaselineCount <= 0) {
                throw new IllegalStateException("SaaS baseline signal minimumUserBaselineCount must be greater than zero");
            }
            if (hourBucketLimit <= 0) {
                throw new IllegalStateException("SaaS baseline signal hourBucketLimit must be greater than zero");
            }
            if (dayBucketLimit <= 0) {
                throw new IllegalStateException("SaaS baseline signal dayBucketLimit must be greater than zero");
            }
            if (operatingSystemLimit <= 0) {
                throw new IllegalStateException("SaaS baseline signal operatingSystemLimit must be greater than zero");
            }
            if (industryCategory == null || industryCategory.isBlank()) {
                throw new IllegalStateException("SaaS baseline signal industryCategory must be configured");
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
                throw new IllegalStateException("SaaS forwarding OAuth2 scope must include saas.baseline.ingest when baseline signal sharing is enabled");
            }
            if (!seedReadScopePresent) {
                throw new IllegalStateException("SaaS forwarding OAuth2 scope must include saas.baseline-seed.read when baseline signal sharing is enabled");
            }
        }
    }

    @Getter
    @Builder
    public static class ThreatIntelligence {

        private final boolean enabled;
        private final String endpointPath;
        private final long pullIntervalMs;
        private final long initialDelayMs;
        private final int signalLimit;
        private final int promptLimit;
        private final int cacheTtlMinutes;

        public void validate(String oauthScopes) {
            if (!enabled) {
                return;
            }
            if (endpointPath == null || endpointPath.isBlank()) {
                throw new IllegalStateException("SaaS threat intelligence endpointPath must be configured");
            }
            if (pullIntervalMs <= 0L) {
                throw new IllegalStateException("SaaS threat intelligence pullIntervalMs must be greater than zero");
            }
            if (initialDelayMs < 0L) {
                throw new IllegalStateException("SaaS threat intelligence initialDelayMs must not be negative");
            }
            if (signalLimit <= 0) {
                throw new IllegalStateException("SaaS threat intelligence signalLimit must be greater than zero");
            }
            if (promptLimit <= 0) {
                throw new IllegalStateException("SaaS threat intelligence promptLimit must be greater than zero");
            }
            if (cacheTtlMinutes <= 0) {
                throw new IllegalStateException("SaaS threat intelligence cacheTtlMinutes must be greater than zero");
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
                throw new IllegalStateException("SaaS forwarding OAuth2 scope must include saas.threat-intelligence.read when threat intelligence pull is enabled");
            }
        }
    }

    @Getter
    @Builder
    public static class ThreatOutcome {

        private final boolean enabled;
        private final String endpointPath;

        public void validate(String oauthScopes) {
            if (!enabled) {
                return;
            }
            if (endpointPath == null || endpointPath.isBlank()) {
                throw new IllegalStateException("SaaS threat outcome endpointPath must be configured");
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
                throw new IllegalStateException("SaaS forwarding OAuth2 scope must include saas.threat-outcome.ingest when threat outcome forwarding is enabled");
            }
        }
    }

    @Getter
    @Builder
    public static class ThreatKnowledge {

        private final boolean enabled;
        private final String endpointPath;
        private final String runtimePolicyEndpointPath;
        private final long pullIntervalMs;
        private final long initialDelayMs;
        private final int caseLimit;
        private final int promptLimit;
        private final int cacheTtlMinutes;

        public void validate(String oauthScopes) {
            if (!enabled) {
                return;
            }
            if (endpointPath == null || endpointPath.isBlank()) {
                throw new IllegalStateException("SaaS threat knowledge endpointPath must be configured");
            }
            if (runtimePolicyEndpointPath == null || runtimePolicyEndpointPath.isBlank()) {
                throw new IllegalStateException("SaaS threat knowledge runtimePolicyEndpointPath must be configured");
            }
            if (pullIntervalMs <= 0L) {
                throw new IllegalStateException("SaaS threat knowledge pullIntervalMs must be greater than zero");
            }
            if (initialDelayMs < 0L) {
                throw new IllegalStateException("SaaS threat knowledge initialDelayMs must not be negative");
            }
            if (caseLimit <= 0) {
                throw new IllegalStateException("SaaS threat knowledge caseLimit must be greater than zero");
            }
            if (promptLimit <= 0) {
                throw new IllegalStateException("SaaS threat knowledge promptLimit must be greater than zero");
            }
            if (cacheTtlMinutes <= 0) {
                throw new IllegalStateException("SaaS threat knowledge cacheTtlMinutes must be greater than zero");
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
                throw new IllegalStateException("SaaS forwarding OAuth2 scope must include saas.threat-knowledge.read when threat knowledge pull is enabled");
            }
        }
    }

    @Getter
    @Builder
    public static class PerformanceTelemetry {

        private final boolean enabled;
        private final String endpointPath;
        private final long publishIntervalMs;
        private final long initialDelayMs;

        public void validate(String oauthScopes) {
            if (!enabled) {
                return;
            }
            if (endpointPath == null || endpointPath.isBlank()) {
                throw new IllegalStateException("SaaS performance telemetry endpointPath must be configured");
            }
            if (publishIntervalMs <= 0L) {
                throw new IllegalStateException("SaaS performance telemetry publishIntervalMs must be greater than zero");
            }
            if (initialDelayMs < 0L) {
                throw new IllegalStateException("SaaS performance telemetry initialDelayMs must not be negative");
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
                throw new IllegalStateException("SaaS forwarding OAuth2 scope must include saas.telemetry.ingest when performance telemetry forwarding is enabled");
            }
        }
    }

    @Getter
    @Builder
    public static class PromptContextAudit {

        private final boolean enabled;
        private final String endpointPath;

        public void validate(String oauthScopes) {
            if (!enabled) {
                return;
            }
            if (endpointPath == null || endpointPath.isBlank()) {
                throw new IllegalStateException("SaaS prompt context audit endpointPath must be configured");
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
                throw new IllegalStateException("SaaS forwarding OAuth2 scope must include saas.prompt-context-audit.ingest when prompt context audit forwarding is enabled");
            }
        }
    }
}
