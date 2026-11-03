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
package io.contexa.autoconfigure.core.autonomous;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.core.CoreDataAutoConfiguration;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventObserver;
import io.contexa.contexacore.autonomous.handler.handler.SaasForwardingHandler;
import io.contexa.contexacore.autonomous.saas.*;
import io.contexa.contexacore.autonomous.saas.client.*;
import io.contexa.contexacore.autonomous.saas.mapper.DecisionFeedbackPayloadMapper;
import io.contexa.contexacore.autonomous.saas.mapper.PromptContextAuditPayloadMapper;
import io.contexa.contexacore.autonomous.saas.mapper.SecurityDecisionForwardingPayloadMapper;
import io.contexa.contexacore.autonomous.saas.mapper.ThreatOutcomePayloadMapper;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactRuntimeConflictService;
import io.contexa.contexacore.autonomous.saas.security.TenantScopedPseudonymizationService;
import io.contexa.contexacore.autonomous.saas.threat.ThreatSignalNormalizationService;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import io.contexa.contexacore.repository.*;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.concurrent.Executor;

@AutoConfiguration(after = CoreDataAutoConfiguration.class)
@ConditionalOnClass(OAuth2AuthorizedClientManager.class)
@ConditionalOnProperty(prefix = "contexa.saas", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(ContexaProperties.class)
public class CoreSaasForwardingAutoConfiguration {

    @Bean(name = "contexaSaasClientRegistrationRepository")
    @ConditionalOnMissingBean(name = "contexaSaasClientRegistrationRepository")
    public ClientRegistrationRepository saasClientRegistrationRepository(ContexaProperties properties) {
        ContexaProperties.Saas.Oauth2 oauth2 = properties.getSaas().getOauth2();
        properties.getSaas().validate();
        ClientRegistration registration = ClientRegistration.withRegistrationId(oauth2.getRegistrationId())
                .tokenUri(oauth2.getTokenUri())
                .clientId(oauth2.getClientId())
                .clientSecret(oauth2.getClientSecret())
                .scope(oauth2.getScope().trim().split("[,\\s]+"))
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .build();
        return new InMemoryClientRegistrationRepository(registration);
    }

    @Bean(name = "contexaSaasOAuth2AuthorizedClientService")
    @ConditionalOnMissingBean(name = "contexaSaasOAuth2AuthorizedClientService")
    public OAuth2AuthorizedClientService saasOAuth2AuthorizedClientService(
            @Qualifier("contexaSaasClientRegistrationRepository") ClientRegistrationRepository registrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(registrationRepository);
    }

    @Bean(name = "contexaSaasOAuth2AuthorizedClientManager")
    @ConditionalOnMissingBean(name = "contexaSaasOAuth2AuthorizedClientManager")
    public OAuth2AuthorizedClientManager saasOAuth2AuthorizedClientManager(
            @Qualifier("contexaSaasClientRegistrationRepository") ClientRegistrationRepository registrationRepository,
            @Qualifier("contexaSaasOAuth2AuthorizedClientService") OAuth2AuthorizedClientService authorizedClientService) {
        AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(registrationRepository, authorizedClientService);
        OAuth2AuthorizedClientProvider provider = OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials()
                .build();
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    @Bean(name = "contexaSaasForwardingProperties")
    @ConditionalOnMissingBean
    public SaasForwardingProperties saasForwardingProperties(ContexaProperties properties) {
        ContexaProperties.Saas source = properties.getSaas();
        // Also enforced here so that a custom saasClientRegistrationRepository cannot bypass it.
        source.validateSecrets();
        return SaasForwardingProperties.builder()
                .enabled(source.isEnabled())
                .endpoint(source.getEndpoint())
                .includeReasoning(source.isIncludeReasoning())
                .includeRawAnalysisData(source.isIncludeRawAnalysisData())
                .outboxBatchSize(source.getOutboxBatchSize())
                .maxRetryAttempts(source.getMaxRetryAttempts())
                .retryInitialBackoffMs(source.getRetryInitialBackoffMs())
                .retryMaxBackoffMs(source.getRetryMaxBackoffMs())
                .dispatchIntervalMs(source.getDispatchIntervalMs())
                .pseudonymizationSecret(source.getPseudonymizationSecret())
                .globalCorrelationSecret(source.getGlobalCorrelationSecret())
                .oauth2(SaasForwardingProperties.OAuth2.builder()
                        .enabled(source.getOauth2().isEnabled())
                        .registrationId(source.getOauth2().getRegistrationId())
                        .tokenUri(source.getOauth2().getTokenUri())
                        .clientId(source.getOauth2().getClientId())
                        .clientSecret(source.getOauth2().getClientSecret())
                        .scope(source.getOauth2().getScope())
                        .expirySkewSeconds(source.getOauth2().getExpirySkewSeconds())
                        .build())
                .decisionFeedback(SaasForwardingProperties.DecisionFeedback.builder()
                        .enabled(source.getDecisionFeedback().isEnabled())
                        .endpointPath(source.getDecisionFeedback().getEndpointPath())
                        .build())
                .baselineSignal(SaasForwardingProperties.BaselineSignal.builder()
                        .enabled(source.getBaselineSignal().isEnabled())
                        .endpointPath(source.getBaselineSignal().getEndpointPath())
                        .seedEndpointPath(source.getBaselineSignal().getSeedEndpointPath())
                        .publishIntervalMs(source.getBaselineSignal().getPublishIntervalMs())
                        .initialDelayMs(source.getBaselineSignal().getInitialDelayMs())
                        .seedPullIntervalMs(source.getBaselineSignal().getSeedPullIntervalMs())
                        .seedInitialDelayMs(source.getBaselineSignal().getSeedInitialDelayMs())
                        .seedCacheTtlMinutes(source.getBaselineSignal().getSeedCacheTtlMinutes())
                        .minimumOrganizationBaselineCount(source.getBaselineSignal().getMinimumOrganizationBaselineCount())
                        .minimumUserBaselineCount(source.getBaselineSignal().getMinimumUserBaselineCount())
                        .hourBucketLimit(source.getBaselineSignal().getHourBucketLimit())
                        .dayBucketLimit(source.getBaselineSignal().getDayBucketLimit())
                        .operatingSystemLimit(source.getBaselineSignal().getOperatingSystemLimit())
                        .industryCategory(source.getBaselineSignal().getIndustryCategory())
                        .build())
                .threatIntelligence(SaasForwardingProperties.ThreatIntelligence.builder()
                        .enabled(source.getThreatIntelligence().isEnabled())
                        .endpointPath(source.getThreatIntelligence().getEndpointPath())
                        .pullIntervalMs(source.getThreatIntelligence().getPullIntervalMs())
                        .initialDelayMs(source.getThreatIntelligence().getInitialDelayMs())
                        .signalLimit(source.getThreatIntelligence().getSignalLimit())
                        .promptLimit(source.getThreatIntelligence().getPromptLimit())
                        .cacheTtlMinutes(source.getThreatIntelligence().getCacheTtlMinutes())
                        .build())
                .threatOutcome(SaasForwardingProperties.ThreatOutcome.builder()
                        .enabled(source.getThreatOutcome().isEnabled())
                        .endpointPath(source.getThreatOutcome().getEndpointPath())
                        .build())

                .detectionStrategy(SaasForwardingProperties.DetectionStrategy.builder()
                        .enabled(source.getDetectionStrategy().isEnabled())
                        .endpointPath(source.getDetectionStrategy().getEndpointPath())
                        .pullIntervalMs(source.getDetectionStrategy().getPullIntervalMs())
                        .initialDelayMs(source.getDetectionStrategy().getInitialDelayMs())
                        .strategyLimit(source.getDetectionStrategy().getStrategyLimit())
                        .promptLimit(source.getDetectionStrategy().getPromptLimit())
                        .cacheTtlMinutes(source.getDetectionStrategy().getCacheTtlMinutes())
                        .build())
                .performanceTelemetry(SaasForwardingProperties.PerformanceTelemetry.builder()
                        .enabled(source.getPerformanceTelemetry().isEnabled())
                        .endpointPath(source.getPerformanceTelemetry().getEndpointPath())
                        .publishIntervalMs(source.getPerformanceTelemetry().getPublishIntervalMs())
                        .initialDelayMs(source.getPerformanceTelemetry().getInitialDelayMs())
                        .build())
                .promptContextAudit(SaasForwardingProperties.PromptContextAudit.builder()
                        .enabled(source.getPromptContextAudit().isEnabled())
                        .endpointPath(source.getPromptContextAudit().getEndpointPath())
                        .build())
                .build();
    }

    @Bean(name = "contexaSaasDecisionAccessTokenProvider")
    @ConditionalOnMissingBean
    public SaasDecisionAccessTokenProvider saasDecisionAccessTokenProvider(
            SaasForwardingProperties properties,
            @Qualifier("contexaSaasOAuth2AuthorizedClientManager") OAuth2AuthorizedClientManager contexaAuthorizedClientManager) {
        return new SaasDecisionAccessTokenProvider(properties, contexaAuthorizedClientManager);
    }

    @Bean(name = "contexaTenantScopedPseudonymizationService")
    @ConditionalOnMissingBean
    public TenantScopedPseudonymizationService tenantScopedPseudonymizationService(SaasForwardingProperties properties) {
        return new TenantScopedPseudonymizationService(properties);
    }

    @Bean(name = "contexaThreatSignalNormalizationService")
    @ConditionalOnMissingBean
    public ThreatSignalNormalizationService threatSignalNormalizationService() {
        return new ThreatSignalNormalizationService();
    }

    @Bean(name = "contexaSecurityDecisionForwardingPayloadMapper")
    @ConditionalOnMissingBean
    public SecurityDecisionForwardingPayloadMapper securityDecisionForwardingPayloadMapper(
            TenantScopedPseudonymizationService pseudonymizationService,
            ThreatSignalNormalizationService contexaThreatSignalNormalizationService,
            SaasForwardingProperties properties,
            ObjectProvider<CanonicalSecurityContextProvider> canonicalSecurityContextProvider) {
        return new SecurityDecisionForwardingPayloadMapper(
                pseudonymizationService,
                contexaThreatSignalNormalizationService,
                properties,
                canonicalSecurityContextProvider.getIfAvailable());
    }

    @Bean(name = "contexaDecisionFeedbackPayloadMapper")
    @ConditionalOnMissingBean
    public DecisionFeedbackPayloadMapper decisionFeedbackPayloadMapper(
            TenantScopedPseudonymizationService pseudonymizationService) {
        return new DecisionFeedbackPayloadMapper(pseudonymizationService);
    }

    @Bean(name = "contexaThreatOutcomePayloadMapper")
    @ConditionalOnMissingBean
    public ThreatOutcomePayloadMapper threatOutcomePayloadMapper(
            TenantScopedPseudonymizationService pseudonymizationService) {
        return new ThreatOutcomePayloadMapper(pseudonymizationService);
    }

    @Bean(name = "contexaPromptContextAuditPayloadMapper")
    @ConditionalOnMissingBean
    public PromptContextAuditPayloadMapper promptContextAuditPayloadMapper(
            TenantScopedPseudonymizationService pseudonymizationService) {
        return new PromptContextAuditPayloadMapper(pseudonymizationService);
    }

    @Bean(name = "contexaSaasDecisionHttpClient")
    @ConditionalOnMissingBean
    public SaasDecisionHttpClient saasDecisionHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasDecisionHttpClient(properties, accessTokenProvider);
    }

    @Bean(name = "contexaSaasDecisionFeedbackHttpClient")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.decision-feedback", name = "enabled", havingValue = "true")
    public SaasDecisionFeedbackHttpClient saasDecisionFeedbackHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasDecisionFeedbackHttpClient(properties, accessTokenProvider);
    }

    @Bean(name = "contexaSaasBaselineSignalHttpClient")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.baseline-signal", name = "enabled", havingValue = "true")
    public SaasBaselineSignalHttpClient saasBaselineSignalHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasBaselineSignalHttpClient(properties, accessTokenProvider);
    }

    @Bean(name = "contexaSaasBaselineSeedHttpClient")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.baseline-signal", name = "enabled", havingValue = "true")
    public SaasBaselineSeedHttpClient saasBaselineSeedHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasBaselineSeedHttpClient(properties, accessTokenProvider);
    }

    @Bean(name = "contexaBaselineSignalAggregationService")
    @ConditionalOnMissingBean
    @ConditionalOnBean({BaselineDataStore.class, BaselineSignalOutboxRepository.class})
    @ConditionalOnProperty(prefix = "contexa.saas.baseline-signal", name = "enabled", havingValue = "true")
    public BaselineSignalAggregationService baselineSignalAggregationService(
            BaselineDataStore contexaBaselineDataStore,
            BaselineSignalOutboxRepository baselineSignalOutboxRepository,
            SaasForwardingProperties properties) {
        return new BaselineSignalAggregationService(
                contexaBaselineDataStore,
                baselineSignalOutboxRepository,
                properties);
    }

    @Bean(name = "contexaSaasBaselineSignalDispatcher")
    @ConditionalOnMissingBean
    @ConditionalOnBean({BaselineSignalOutboxRepository.class, SaasBaselineSignalHttpClient.class})
    public SaasBaselineSignalDispatcher saasBaselineSignalDispatcher(
            BaselineSignalOutboxRepository repository,
            SaasBaselineSignalHttpClient httpClient,
            SaasForwardingProperties properties) {
        return new SaasBaselineSignalDispatcher(repository, httpClient, properties);
    }

    @Bean(name = "contexaSaasBaselineSeedService")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasBaselineSeedHttpClient.class)
    public SaasBaselineSeedService saasBaselineSeedService(
            SaasForwardingProperties properties,
            SaasBaselineSeedHttpClient httpClient) {
        return new SaasBaselineSeedService(properties, httpClient);
    }

    @Bean(name = "contexaSaasBaselineSignalScheduler")
    @ConditionalOnMissingBean
    @ConditionalOnBean({BaselineSignalAggregationService.class, SaasBaselineSignalDispatcher.class})
    public SaasBaselineSignalScheduler saasBaselineSignalScheduler(
            BaselineSignalAggregationService aggregationService,
            SaasBaselineSignalDispatcher dispatcher,
            SaasForwardingProperties properties) {
        return new SaasBaselineSignalScheduler(aggregationService, dispatcher, properties);
    }

    @Bean(name = "contexaSaasBaselineSeedPullScheduler")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasBaselineSeedService.class)
    public SaasBaselineSeedPullScheduler saasBaselineSeedPullScheduler(
            SaasBaselineSeedService baselineSeedService,
            SaasForwardingProperties properties) {
        return new SaasBaselineSeedPullScheduler(baselineSeedService, properties);
    }

    @Bean(name = "contexaSaasThreatIntelligenceHttpClient")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.threat-intelligence", name = "enabled", havingValue = "true")
    public SaasThreatIntelligenceHttpClient saasThreatIntelligenceHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasThreatIntelligenceHttpClient(properties, accessTokenProvider);
    }

    @Bean(name = "contexaSaasThreatOutcomeHttpClient")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.threat-outcome", name = "enabled", havingValue = "true")
    public SaasThreatOutcomeHttpClient saasThreatOutcomeHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasThreatOutcomeHttpClient(properties, accessTokenProvider);
    }

    @Bean(name = "contexaSaasThreatKnowledgePackHttpClient")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.threat-knowledge", name = "enabled", havingValue = "true")
    public SaasThreatKnowledgePackHttpClient saasThreatKnowledgePackHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasThreatKnowledgePackHttpClient(properties, accessTokenProvider);
    }

    @Bean(name = "contexaSaasThreatKnowledgeRuntimePolicyHttpClient")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.threat-knowledge", name = "enabled", havingValue = "true")
    public SaasThreatKnowledgeRuntimePolicyHttpClient saasThreatKnowledgeRuntimePolicyHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasThreatKnowledgeRuntimePolicyHttpClient(properties, accessTokenProvider);
    }

    @Bean(name = "contexaSaasDetectionStrategyPackHttpClient")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.detection-strategy", name = "enabled", havingValue = "true")
    public SaasDetectionStrategyPackHttpClient saasDetectionStrategyPackHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasDetectionStrategyPackHttpClient(properties, accessTokenProvider);
    }

    @Bean(name = "contexaSaasThreatIntelligenceService")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasThreatIntelligenceHttpClient.class)
    public SaasThreatIntelligenceService saasThreatIntelligenceService(
            SaasForwardingProperties properties,
            SaasThreatIntelligenceHttpClient httpClient) {
        return new SaasThreatIntelligenceService(properties, httpClient);
    }

    @Bean(name = "contexaSaasThreatKnowledgePackService")
    @ConditionalOnMissingBean
    @ConditionalOnBean({SaasThreatKnowledgePackHttpClient.class, SaasThreatKnowledgeRuntimePolicyService.class})
    public SaasThreatKnowledgePackService saasThreatKnowledgePackService(
            SaasForwardingProperties properties,
            SaasThreatKnowledgePackHttpClient httpClient,
            SaasThreatKnowledgeRuntimePolicyService runtimePolicyService) {
        return new SaasThreatKnowledgePackService(properties, httpClient, runtimePolicyService);
    }

    @Bean(name = "contexaSaasDetectionStrategyPackService")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasDetectionStrategyPackHttpClient.class)
    public SaasDetectionStrategyPackService saasDetectionStrategyPackService(
            SaasForwardingProperties properties,
            SaasDetectionStrategyPackHttpClient httpClient,
            ObjectProvider<LearningArtifactRuntimeConflictService> runtimeConflictService) {
        return new SaasDetectionStrategyPackService(properties, httpClient, runtimeConflictService.getIfAvailable());
    }

    @Bean(name = "contexaSaasThreatKnowledgeRuntimePolicyService")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasThreatKnowledgeRuntimePolicyHttpClient.class)
    public SaasThreatKnowledgeRuntimePolicyService saasThreatKnowledgeRuntimePolicyService(
            SaasForwardingProperties properties,
            SaasThreatKnowledgeRuntimePolicyHttpClient httpClient) {
        return new SaasThreatKnowledgeRuntimePolicyService(properties, httpClient);
    }
    @Bean(name = "contexaSaasModelPerformanceTelemetryHttpClient")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.performance-telemetry", name = "enabled", havingValue = "true")
    public SaasModelPerformanceTelemetryHttpClient saasModelPerformanceTelemetryHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasModelPerformanceTelemetryHttpClient(properties, accessTokenProvider);
    }

    @Bean(name = "contexaSaasPromptContextAuditHttpClient")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.prompt-context-audit", name = "enabled", havingValue = "true")
    public SaasPromptContextAuditHttpClient saasPromptContextAuditHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasPromptContextAuditHttpClient(properties, accessTokenProvider);
    }

    @Bean(name = "contexaModelPerformanceTelemetryCollector")
    @ConditionalOnMissingBean
    @ConditionalOnBean(ModelPerformanceTelemetryOutboxRepository.class)
    @ConditionalOnProperty(prefix = "contexa.saas.performance-telemetry", name = "enabled", havingValue = "true")
    public ModelPerformanceTelemetryCollector modelPerformanceTelemetryCollector(
            ModelPerformanceTelemetryOutboxRepository repository,
            SaasForwardingProperties properties) {
        return new ModelPerformanceTelemetryCollector(repository, properties);
    }

    @Bean(name = "contexaModelPerformanceTelemetryObserver")
    @ConditionalOnMissingBean(name = "contexaModelPerformanceTelemetryObserver")
    @ConditionalOnBean(ModelPerformanceTelemetryCollector.class)
    public LlmAnalysisEventObserver modelPerformanceTelemetryObserver(ModelPerformanceTelemetryCollector collector) {
        return collector;
    }

    @Bean(name = "contexaSaasModelPerformanceTelemetryDispatcher")
    @ConditionalOnMissingBean
    @ConditionalOnBean({ModelPerformanceTelemetryOutboxRepository.class, SaasModelPerformanceTelemetryHttpClient.class})
    public SaasModelPerformanceTelemetryDispatcher saasModelPerformanceTelemetryDispatcher(
            ModelPerformanceTelemetryOutboxRepository repository,
            SaasModelPerformanceTelemetryHttpClient httpClient,
            SaasForwardingProperties properties) {
        return new SaasModelPerformanceTelemetryDispatcher(repository, httpClient, properties);
    }

    @Bean(name = "contexaSaasPromptContextAuditDispatcher")
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptContextAuditForwardingOutboxRepository.class, SaasPromptContextAuditHttpClient.class})
    public SaasPromptContextAuditDispatcher saasPromptContextAuditDispatcher(
            PromptContextAuditForwardingOutboxRepository repository,
            SaasPromptContextAuditHttpClient httpClient,
            SaasForwardingProperties properties) {
        return new SaasPromptContextAuditDispatcher(repository, httpClient, properties);
    }

    @Bean(name = "contexaSaasModelPerformanceTelemetryScheduler")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasModelPerformanceTelemetryDispatcher.class)
    public SaasModelPerformanceTelemetryScheduler saasModelPerformanceTelemetryScheduler(
            SaasModelPerformanceTelemetryDispatcher dispatcher,
            SaasForwardingProperties properties) {
        return new SaasModelPerformanceTelemetryScheduler(dispatcher, properties);
    }

    @Bean(name = "contexaSaasThreatSignalPullScheduler")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasThreatIntelligenceService.class)
    public SaasThreatSignalPullScheduler saasThreatSignalPullScheduler(
            SaasThreatIntelligenceService threatIntelligenceService,
            SaasForwardingProperties properties) {
        return new SaasThreatSignalPullScheduler(threatIntelligenceService, properties);
    }

    @Bean(name = "contexaSaasThreatKnowledgePackPullScheduler")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasThreatKnowledgePackService.class)
    public SaasThreatKnowledgePackPullScheduler saasThreatKnowledgePackPullScheduler(
            SaasThreatKnowledgePackService threatKnowledgePackService,
            SaasForwardingProperties properties) {
        return new SaasThreatKnowledgePackPullScheduler(threatKnowledgePackService, properties);
    }

    @Bean(name = "contexaSaasDetectionStrategyPackPullScheduler")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasDetectionStrategyPackService.class)
    public SaasDetectionStrategyPackPullScheduler saasDetectionStrategyPackPullScheduler(
            SaasDetectionStrategyPackService detectionStrategyPackService,
            SaasForwardingProperties properties) {
        return new SaasDetectionStrategyPackPullScheduler(detectionStrategyPackService, properties);
    }
    @Bean(name = "contexaSaasThreatKnowledgeRuntimePolicyPullScheduler")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasThreatKnowledgeRuntimePolicyService.class)
    public SaasThreatKnowledgeRuntimePolicyPullScheduler saasThreatKnowledgeRuntimePolicyPullScheduler(
            SaasThreatKnowledgeRuntimePolicyService runtimePolicyService,
            SaasForwardingProperties properties) {
        return new SaasThreatKnowledgeRuntimePolicyPullScheduler(runtimePolicyService, properties);
    }

    @Bean(name = "contexaSaasDecisionDispatcher")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SecurityDecisionForwardingOutboxRepository.class)
    public SaasDecisionDispatcher saasDecisionDispatcher(
            SecurityDecisionForwardingOutboxRepository repository,
            SaasDecisionHttpClient httpClient,
            SaasForwardingProperties properties) {
        return new SaasDecisionDispatcher(repository, httpClient, properties);
    }

    @Bean(name = "contexaSaasDecisionFeedbackDispatcher")
    @ConditionalOnMissingBean
    @ConditionalOnBean({DecisionFeedbackForwardingOutboxRepository.class, SaasDecisionFeedbackHttpClient.class})
    public SaasDecisionFeedbackDispatcher saasDecisionFeedbackDispatcher(
            DecisionFeedbackForwardingOutboxRepository repository,
            SaasDecisionFeedbackHttpClient httpClient,
            SaasForwardingProperties properties) {
        return new SaasDecisionFeedbackDispatcher(repository, httpClient, properties);
    }

    @Bean(name = "contexaSaasThreatOutcomeDispatcher")
    @ConditionalOnMissingBean
    @ConditionalOnBean({ThreatOutcomeForwardingOutboxRepository.class, SaasThreatOutcomeHttpClient.class})
    public SaasThreatOutcomeDispatcher saasThreatOutcomeDispatcher(
            ThreatOutcomeForwardingOutboxRepository repository,
            SaasThreatOutcomeHttpClient httpClient,
            SaasForwardingProperties properties) {
        return new SaasThreatOutcomeDispatcher(repository, httpClient, properties);
    }

    @Bean(name = "contexaSaasDecisionOutboxService")
    @ConditionalOnMissingBean
    @ConditionalOnBean({SecurityDecisionForwardingOutboxRepository.class, SaasDecisionDispatcher.class})
    public SaasDecisionOutboxService saasDecisionOutboxService(
            SecurityDecisionForwardingOutboxRepository repository,
            SecurityDecisionForwardingPayloadMapper payloadMapper,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
            SaasDecisionDispatcher dispatcher,
            @Qualifier("contexaSaasForwardingExecutor") Executor executor) {
        return new SaasDecisionOutboxService(repository, payloadMapper, objectMapper, dispatcher, executor);
    }

    @Bean(name = "contexaSaasDecisionFeedbackOutboxService")
    @ConditionalOnMissingBean(DecisionFeedbackForwardingService.class)
    @ConditionalOnBean({DecisionFeedbackForwardingOutboxRepository.class, SaasDecisionFeedbackDispatcher.class})
    public DecisionFeedbackForwardingService saasDecisionFeedbackOutboxService(
            DecisionFeedbackForwardingOutboxRepository repository,
            DecisionFeedbackPayloadMapper payloadMapper,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
            SaasDecisionFeedbackDispatcher dispatcher,
            @Qualifier("contexaSaasForwardingExecutor") Executor executor) {
        return new SaasDecisionFeedbackOutboxService(repository, payloadMapper, objectMapper, dispatcher, executor);
    }

    @Bean(name = "contexaSaasThreatOutcomeOutboxService")
    @ConditionalOnMissingBean(ThreatOutcomeForwardingService.class)
    @ConditionalOnBean({ThreatOutcomeForwardingOutboxRepository.class, SaasThreatOutcomeDispatcher.class})
    public SaasThreatOutcomeOutboxService saasThreatOutcomeOutboxService(
            ThreatOutcomeForwardingOutboxRepository repository,
            ThreatOutcomePayloadMapper payloadMapper,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
            SaasThreatOutcomeDispatcher dispatcher,
            @Qualifier("contexaSaasForwardingExecutor") Executor executor) {
        return new SaasThreatOutcomeOutboxService(repository, payloadMapper, objectMapper, dispatcher, executor);
    }

    @Bean(name = "contexaPromptContextAuditForwardingService")
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptContextAuditForwardingOutboxRepository.class, SaasPromptContextAuditDispatcher.class})
    public PromptContextAuditForwardingService promptContextAuditForwardingService(
            PromptContextAuditForwardingOutboxRepository repository,
            PromptContextAuditPayloadMapper payloadMapper,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
            SaasPromptContextAuditDispatcher dispatcher,
            @Qualifier("contexaSaasForwardingExecutor") Executor executor) {
        return new PromptContextAuditForwardingService(repository, payloadMapper, objectMapper, dispatcher, executor);
    }

    @Bean(name = "contexaSaasOutboxRetryScheduler")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasDecisionDispatcher.class)
    public SaasOutboxRetryScheduler saasOutboxRetryScheduler(
            SaasDecisionDispatcher dispatcher,
            SaasForwardingProperties properties) {
        return new SaasOutboxRetryScheduler(dispatcher, properties);
    }

    @Bean(name = "contexaSaasDecisionFeedbackRetryScheduler")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasDecisionFeedbackDispatcher.class)
    public SaasDecisionFeedbackRetryScheduler saasDecisionFeedbackRetryScheduler(
            SaasDecisionFeedbackDispatcher dispatcher,
            SaasForwardingProperties properties) {
        return new SaasDecisionFeedbackRetryScheduler(dispatcher, properties);
    }

    @Bean(name = "contexaSaasThreatOutcomeRetryScheduler")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasThreatOutcomeDispatcher.class)
    public SaasThreatOutcomeRetryScheduler saasThreatOutcomeRetryScheduler(
            SaasThreatOutcomeDispatcher dispatcher,
            SaasForwardingProperties properties) {
        return new SaasThreatOutcomeRetryScheduler(dispatcher, properties);
    }

    @Bean(name = "contexaSaasPromptContextAuditRetryScheduler")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasPromptContextAuditDispatcher.class)
    public SaasPromptContextAuditRetryScheduler saasPromptContextAuditRetryScheduler(
            SaasPromptContextAuditDispatcher dispatcher,
            SaasForwardingProperties properties) {
        return new SaasPromptContextAuditRetryScheduler(dispatcher, properties);
    }

    @Bean(name = "contexaSaasForwardingHandler")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasDecisionOutboxService.class)
    public SaasForwardingHandler saasForwardingHandler(
            SaasDecisionOutboxService outboxService,
            SaasForwardingProperties properties) {
        return new SaasForwardingHandler(outboxService, properties);
    }
}
