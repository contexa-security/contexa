package io.contexa.autoconfigure.core.autonomous;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import io.contexa.contexacore.autonomous.saas.security.TenantScopedPseudonymizationService;
import io.contexa.contexacore.autonomous.saas.threat.ThreatSignalNormalizationService;
import io.contexa.contexacore.hcad.store.BaselineDataStore;
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

@AutoConfiguration
@ConditionalOnClass(OAuth2AuthorizedClientManager.class)
@ConditionalOnProperty(prefix = "contexa.saas", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(ContexaProperties.class)
public class CoreSaasForwardingAutoConfiguration {

    @Bean(name = "saasClientRegistrationRepository")
    @ConditionalOnMissingBean(name = "saasClientRegistrationRepository")
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

    @Bean(name = "saasOAuth2AuthorizedClientService")
    @ConditionalOnMissingBean(name = "saasOAuth2AuthorizedClientService")
    public OAuth2AuthorizedClientService saasOAuth2AuthorizedClientService(
            @Qualifier("saasClientRegistrationRepository") ClientRegistrationRepository registrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(registrationRepository);
    }

    @Bean(name = "saasOAuth2AuthorizedClientManager")
    @ConditionalOnMissingBean(name = "saasOAuth2AuthorizedClientManager")
    public OAuth2AuthorizedClientManager saasOAuth2AuthorizedClientManager(
            @Qualifier("saasClientRegistrationRepository") ClientRegistrationRepository registrationRepository,
            @Qualifier("saasOAuth2AuthorizedClientService") OAuth2AuthorizedClientService authorizedClientService) {
        AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(registrationRepository, authorizedClientService);
        OAuth2AuthorizedClientProvider provider = OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials()
                .build();
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    @Bean
    @ConditionalOnMissingBean
    public SaasForwardingProperties saasForwardingProperties(ContexaProperties properties) {
        ContexaProperties.Saas source = properties.getSaas();
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
                .threatKnowledge(SaasForwardingProperties.ThreatKnowledge.builder()
                        .enabled(source.getThreatKnowledge().isEnabled())
                        .endpointPath(source.getThreatKnowledge().getEndpointPath())
                        .runtimePolicyEndpointPath(source.getThreatKnowledge().getRuntimePolicyEndpointPath())
                        .pullIntervalMs(source.getThreatKnowledge().getPullIntervalMs())
                        .initialDelayMs(source.getThreatKnowledge().getInitialDelayMs())
                        .caseLimit(source.getThreatKnowledge().getCaseLimit())
                        .promptLimit(source.getThreatKnowledge().getPromptLimit())
                        .cacheTtlMinutes(source.getThreatKnowledge().getCacheTtlMinutes())
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

    @Bean
    @ConditionalOnMissingBean
    public SaasDecisionAccessTokenProvider saasDecisionAccessTokenProvider(
            SaasForwardingProperties properties,
            @Qualifier("saasOAuth2AuthorizedClientManager") OAuth2AuthorizedClientManager authorizedClientManager) {
        return new SaasDecisionAccessTokenProvider(properties, authorizedClientManager);
    }

    @Bean
    @ConditionalOnMissingBean
    public TenantScopedPseudonymizationService tenantScopedPseudonymizationService(SaasForwardingProperties properties) {
        return new TenantScopedPseudonymizationService(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public ThreatSignalNormalizationService threatSignalNormalizationService() {
        return new ThreatSignalNormalizationService();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityDecisionForwardingPayloadMapper securityDecisionForwardingPayloadMapper(
            TenantScopedPseudonymizationService pseudonymizationService,
            ThreatSignalNormalizationService threatSignalNormalizationService,
            SaasForwardingProperties properties,
            ObjectProvider<CanonicalSecurityContextProvider> canonicalSecurityContextProvider) {
        return new SecurityDecisionForwardingPayloadMapper(
                pseudonymizationService,
                threatSignalNormalizationService,
                properties,
                canonicalSecurityContextProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public DecisionFeedbackPayloadMapper decisionFeedbackPayloadMapper(
            TenantScopedPseudonymizationService pseudonymizationService) {
        return new DecisionFeedbackPayloadMapper(pseudonymizationService);
    }

    @Bean
    @ConditionalOnMissingBean
    public ThreatOutcomePayloadMapper threatOutcomePayloadMapper(
            TenantScopedPseudonymizationService pseudonymizationService) {
        return new ThreatOutcomePayloadMapper(pseudonymizationService);
    }

    @Bean
    @ConditionalOnMissingBean
    public PromptContextAuditPayloadMapper promptContextAuditPayloadMapper() {
        return new PromptContextAuditPayloadMapper();
    }

    @Bean
    @ConditionalOnMissingBean
    public SaasDecisionHttpClient saasDecisionHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasDecisionHttpClient(properties, accessTokenProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.decision-feedback", name = "enabled", havingValue = "true")
    public SaasDecisionFeedbackHttpClient saasDecisionFeedbackHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasDecisionFeedbackHttpClient(properties, accessTokenProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.baseline-signal", name = "enabled", havingValue = "true")
    public SaasBaselineSignalHttpClient saasBaselineSignalHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasBaselineSignalHttpClient(properties, accessTokenProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.baseline-signal", name = "enabled", havingValue = "true")
    public SaasBaselineSeedHttpClient saasBaselineSeedHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasBaselineSeedHttpClient(properties, accessTokenProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({BaselineDataStore.class, BaselineSignalOutboxRepository.class})
    @ConditionalOnProperty(prefix = "contexa.saas.baseline-signal", name = "enabled", havingValue = "true")
    public BaselineSignalAggregationService baselineSignalAggregationService(
            BaselineDataStore baselineDataStore,
            BaselineSignalOutboxRepository baselineSignalOutboxRepository,
            SaasForwardingProperties properties) {
        return new BaselineSignalAggregationService(
                baselineDataStore,
                baselineSignalOutboxRepository,
                properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({BaselineSignalOutboxRepository.class, SaasBaselineSignalHttpClient.class})
    public SaasBaselineSignalDispatcher saasBaselineSignalDispatcher(
            BaselineSignalOutboxRepository repository,
            SaasBaselineSignalHttpClient httpClient,
            SaasForwardingProperties properties) {
        return new SaasBaselineSignalDispatcher(repository, httpClient, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasBaselineSeedHttpClient.class)
    public SaasBaselineSeedService saasBaselineSeedService(
            SaasForwardingProperties properties,
            SaasBaselineSeedHttpClient httpClient) {
        return new SaasBaselineSeedService(properties, httpClient);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({BaselineSignalAggregationService.class, SaasBaselineSignalDispatcher.class})
    public SaasBaselineSignalScheduler saasBaselineSignalScheduler(
            BaselineSignalAggregationService aggregationService,
            SaasBaselineSignalDispatcher dispatcher,
            SaasForwardingProperties properties) {
        return new SaasBaselineSignalScheduler(aggregationService, dispatcher, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasBaselineSeedService.class)
    public SaasBaselineSeedPullScheduler saasBaselineSeedPullScheduler(
            SaasBaselineSeedService baselineSeedService,
            SaasForwardingProperties properties) {
        return new SaasBaselineSeedPullScheduler(baselineSeedService, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.threat-intelligence", name = "enabled", havingValue = "true")
    public SaasThreatIntelligenceHttpClient saasThreatIntelligenceHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasThreatIntelligenceHttpClient(properties, accessTokenProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.threat-outcome", name = "enabled", havingValue = "true")
    public SaasThreatOutcomeHttpClient saasThreatOutcomeHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasThreatOutcomeHttpClient(properties, accessTokenProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.threat-knowledge", name = "enabled", havingValue = "true")
    public SaasThreatKnowledgePackHttpClient saasThreatKnowledgePackHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasThreatKnowledgePackHttpClient(properties, accessTokenProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.threat-knowledge", name = "enabled", havingValue = "true")
    public SaasThreatKnowledgeRuntimePolicyHttpClient saasThreatKnowledgeRuntimePolicyHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasThreatKnowledgeRuntimePolicyHttpClient(properties, accessTokenProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasThreatIntelligenceHttpClient.class)
    public SaasThreatIntelligenceService saasThreatIntelligenceService(
            SaasForwardingProperties properties,
            SaasThreatIntelligenceHttpClient httpClient) {
        return new SaasThreatIntelligenceService(properties, httpClient);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({SaasThreatKnowledgePackHttpClient.class, SaasThreatKnowledgeRuntimePolicyService.class})
    public SaasThreatKnowledgePackService saasThreatKnowledgePackService(
            SaasForwardingProperties properties,
            SaasThreatKnowledgePackHttpClient httpClient,
            SaasThreatKnowledgeRuntimePolicyService runtimePolicyService) {
        return new SaasThreatKnowledgePackService(properties, httpClient, runtimePolicyService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasThreatKnowledgeRuntimePolicyHttpClient.class)
    public SaasThreatKnowledgeRuntimePolicyService saasThreatKnowledgeRuntimePolicyService(
            SaasForwardingProperties properties,
            SaasThreatKnowledgeRuntimePolicyHttpClient httpClient) {
        return new SaasThreatKnowledgeRuntimePolicyService(properties, httpClient);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.performance-telemetry", name = "enabled", havingValue = "true")
    public SaasModelPerformanceTelemetryHttpClient saasModelPerformanceTelemetryHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasModelPerformanceTelemetryHttpClient(properties, accessTokenProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.saas.prompt-context-audit", name = "enabled", havingValue = "true")
    public SaasPromptContextAuditHttpClient saasPromptContextAuditHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        return new SaasPromptContextAuditHttpClient(properties, accessTokenProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ModelPerformanceTelemetryOutboxRepository.class)
    @ConditionalOnProperty(prefix = "contexa.saas.performance-telemetry", name = "enabled", havingValue = "true")
    public ModelPerformanceTelemetryCollector modelPerformanceTelemetryCollector(
            ModelPerformanceTelemetryOutboxRepository repository,
            SaasForwardingProperties properties) {
        return new ModelPerformanceTelemetryCollector(repository, properties);
    }

    @Bean
    @ConditionalOnMissingBean(name = "modelPerformanceTelemetryObserver")
    @ConditionalOnBean(ModelPerformanceTelemetryCollector.class)
    public LlmAnalysisEventObserver modelPerformanceTelemetryObserver(ModelPerformanceTelemetryCollector collector) {
        return collector;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({ModelPerformanceTelemetryOutboxRepository.class, SaasModelPerformanceTelemetryHttpClient.class})
    public SaasModelPerformanceTelemetryDispatcher saasModelPerformanceTelemetryDispatcher(
            ModelPerformanceTelemetryOutboxRepository repository,
            SaasModelPerformanceTelemetryHttpClient httpClient,
            SaasForwardingProperties properties) {
        return new SaasModelPerformanceTelemetryDispatcher(repository, httpClient, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptContextAuditForwardingOutboxRepository.class, SaasPromptContextAuditHttpClient.class})
    public SaasPromptContextAuditDispatcher saasPromptContextAuditDispatcher(
            PromptContextAuditForwardingOutboxRepository repository,
            SaasPromptContextAuditHttpClient httpClient,
            SaasForwardingProperties properties) {
        return new SaasPromptContextAuditDispatcher(repository, httpClient, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasModelPerformanceTelemetryDispatcher.class)
    public SaasModelPerformanceTelemetryScheduler saasModelPerformanceTelemetryScheduler(
            SaasModelPerformanceTelemetryDispatcher dispatcher,
            SaasForwardingProperties properties) {
        return new SaasModelPerformanceTelemetryScheduler(dispatcher, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasThreatIntelligenceService.class)
    public SaasThreatSignalPullScheduler saasThreatSignalPullScheduler(
            SaasThreatIntelligenceService threatIntelligenceService,
            SaasForwardingProperties properties) {
        return new SaasThreatSignalPullScheduler(threatIntelligenceService, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasThreatKnowledgePackService.class)
    public SaasThreatKnowledgePackPullScheduler saasThreatKnowledgePackPullScheduler(
            SaasThreatKnowledgePackService threatKnowledgePackService,
            SaasForwardingProperties properties) {
        return new SaasThreatKnowledgePackPullScheduler(threatKnowledgePackService, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasThreatKnowledgeRuntimePolicyService.class)
    public SaasThreatKnowledgeRuntimePolicyPullScheduler saasThreatKnowledgeRuntimePolicyPullScheduler(
            SaasThreatKnowledgeRuntimePolicyService runtimePolicyService,
            SaasForwardingProperties properties) {
        return new SaasThreatKnowledgeRuntimePolicyPullScheduler(runtimePolicyService, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SecurityDecisionForwardingOutboxRepository.class)
    public SaasDecisionDispatcher saasDecisionDispatcher(
            SecurityDecisionForwardingOutboxRepository repository,
            SaasDecisionHttpClient httpClient,
            SaasForwardingProperties properties) {
        return new SaasDecisionDispatcher(repository, httpClient, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({DecisionFeedbackForwardingOutboxRepository.class, SaasDecisionFeedbackHttpClient.class})
    public SaasDecisionFeedbackDispatcher saasDecisionFeedbackDispatcher(
            DecisionFeedbackForwardingOutboxRepository repository,
            SaasDecisionFeedbackHttpClient httpClient,
            SaasForwardingProperties properties) {
        return new SaasDecisionFeedbackDispatcher(repository, httpClient, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({ThreatOutcomeForwardingOutboxRepository.class, SaasThreatOutcomeHttpClient.class})
    public SaasThreatOutcomeDispatcher saasThreatOutcomeDispatcher(
            ThreatOutcomeForwardingOutboxRepository repository,
            SaasThreatOutcomeHttpClient httpClient,
            SaasForwardingProperties properties) {
        return new SaasThreatOutcomeDispatcher(repository, httpClient, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({SecurityDecisionForwardingOutboxRepository.class, SaasDecisionDispatcher.class})
    public SaasDecisionOutboxService saasDecisionOutboxService(
            SecurityDecisionForwardingOutboxRepository repository,
            SecurityDecisionForwardingPayloadMapper payloadMapper,
            ObjectMapper objectMapper,
            SaasDecisionDispatcher dispatcher,
            @Qualifier("saasForwardingExecutor") Executor executor) {
        return new SaasDecisionOutboxService(repository, payloadMapper, objectMapper, dispatcher, executor);
    }

    @Bean
    @ConditionalOnMissingBean(DecisionFeedbackForwardingService.class)
    @ConditionalOnBean({DecisionFeedbackForwardingOutboxRepository.class, SaasDecisionFeedbackDispatcher.class})
    public DecisionFeedbackForwardingService saasDecisionFeedbackOutboxService(
            DecisionFeedbackForwardingOutboxRepository repository,
            DecisionFeedbackPayloadMapper payloadMapper,
            ObjectMapper objectMapper,
            SaasDecisionFeedbackDispatcher dispatcher,
            @Qualifier("saasForwardingExecutor") Executor executor) {
        return new SaasDecisionFeedbackOutboxService(repository, payloadMapper, objectMapper, dispatcher, executor);
    }

    @Bean
    @ConditionalOnMissingBean(ThreatOutcomeForwardingService.class)
    @ConditionalOnBean({ThreatOutcomeForwardingOutboxRepository.class, SaasThreatOutcomeDispatcher.class})
    public SaasThreatOutcomeOutboxService saasThreatOutcomeOutboxService(
            ThreatOutcomeForwardingOutboxRepository repository,
            ThreatOutcomePayloadMapper payloadMapper,
            ObjectMapper objectMapper,
            SaasThreatOutcomeDispatcher dispatcher,
            @Qualifier("saasForwardingExecutor") Executor executor) {
        return new SaasThreatOutcomeOutboxService(repository, payloadMapper, objectMapper, dispatcher, executor);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptContextAuditForwardingOutboxRepository.class, SaasPromptContextAuditDispatcher.class})
    public PromptContextAuditForwardingService promptContextAuditForwardingService(
            PromptContextAuditForwardingOutboxRepository repository,
            PromptContextAuditPayloadMapper payloadMapper,
            ObjectMapper objectMapper,
            SaasPromptContextAuditDispatcher dispatcher,
            @Qualifier("saasForwardingExecutor") Executor executor) {
        return new PromptContextAuditForwardingService(repository, payloadMapper, objectMapper, dispatcher, executor);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasDecisionDispatcher.class)
    public SaasOutboxRetryScheduler saasOutboxRetryScheduler(
            SaasDecisionDispatcher dispatcher,
            SaasForwardingProperties properties) {
        return new SaasOutboxRetryScheduler(dispatcher, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasDecisionFeedbackDispatcher.class)
    public SaasDecisionFeedbackRetryScheduler saasDecisionFeedbackRetryScheduler(
            SaasDecisionFeedbackDispatcher dispatcher,
            SaasForwardingProperties properties) {
        return new SaasDecisionFeedbackRetryScheduler(dispatcher, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasThreatOutcomeDispatcher.class)
    public SaasThreatOutcomeRetryScheduler saasThreatOutcomeRetryScheduler(
            SaasThreatOutcomeDispatcher dispatcher,
            SaasForwardingProperties properties) {
        return new SaasThreatOutcomeRetryScheduler(dispatcher, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasPromptContextAuditDispatcher.class)
    public SaasPromptContextAuditRetryScheduler saasPromptContextAuditRetryScheduler(
            SaasPromptContextAuditDispatcher dispatcher,
            SaasForwardingProperties properties) {
        return new SaasPromptContextAuditRetryScheduler(dispatcher, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SaasDecisionOutboxService.class)
    public SaasForwardingHandler saasForwardingHandler(
            SaasDecisionOutboxService outboxService,
            SaasForwardingProperties properties) {
        return new SaasForwardingHandler(outboxService, properties);
    }
}
