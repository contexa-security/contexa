package io.contexa.autoconfigure.core.autonomous;

import io.contexa.autoconfigure.core.hcad.CoreHCADAutoConfiguration;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.SecurityEventProcessor;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.audit.AuditPersistenceListener;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.context.*;
import io.contexa.contexacore.autonomous.event.SecurityEventCollector;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.execution.ZeroTrustExceptionHandler;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.handler.handler.AuditingHandler;
import io.contexa.contexacore.autonomous.mcp.McpSecurityContextProvider;
import io.contexa.contexacore.autonomous.repository.*;
import io.contexa.contexacore.autonomous.saas.*;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import org.springframework.lang.Nullable;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.service.impl.SoarContextProviderImpl;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.utils.InMemoryThreatScoreUtil;
import io.contexa.contexacore.autonomous.utils.RedisThreatScoreUtil;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.infra.lock.InMemoryDistributedLockService;
import io.contexa.contexacore.properties.*;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.List;
import java.util.concurrent.Executor;

@AutoConfiguration
@AutoConfigureAfter(CoreHCADAutoConfiguration.class)
@ConditionalOnProperty(prefix = "contexa.autonomous", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({
        ContexaProperties.class,
        SecurityPlaneProperties.class,
        SecurityEventProperties.class,
        SecurityZeroTrustProperties.class,
        SecuritySessionProperties.class,
        SecurityColdPathProperties.class,
        SecurityKafkaProperties.class,
        SecurityRedisProperties.class,
        SecurityRouterProperties.class,
        SecurityPipelineProperties.class,
        TieredStrategyProperties.class,
        TieredStrategyProperties.class,
        ContexaRagProperties.class
})
public class CoreAutonomousAutoConfiguration {

    public CoreAutonomousAutoConfiguration() {
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityEventEnricher securityEventEnricher() {
        return new SecurityEventEnricher();
    }

    @Bean
    @ConditionalOnMissingBean
    public ResourceContextRegistry resourceContextRegistry() {
        return new InMemoryResourceContextRegistry();
    }

    @Bean
    @ConditionalOnMissingBean
    public ContextCoverageEvaluator contextCoverageEvaluator() {
        return new ContextCoverageEvaluator();
    }

    @Bean
    @ConditionalOnMissingBean
    public CanonicalSecurityContextProvider canonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator contextCoverageEvaluator,
            ObjectProvider<AuthenticationContextProvider> authenticationContextProviders,
            ObjectProvider<AuthorizationSnapshotProvider> authorizationSnapshotProviders,
            ObjectProvider<OrganizationContextProvider> organizationContextProviders,
            ObjectProvider<DelegationContextProvider> delegationContextProviders,
            ObjectProvider<ObservedScopeInferenceService> observedScopeInferenceService) {
        return new DefaultCanonicalSecurityContextProvider(
                resourceContextRegistry,
                contextCoverageEvaluator,
                authenticationContextProviders.orderedStream().toList(),
                authorizationSnapshotProviders.orderedStream().toList(),
                organizationContextProviders.orderedStream().toList(),
                delegationContextProviders.orderedStream().toList(),
                observedScopeInferenceService.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public PromptContextComposer promptContextComposer() {
        return new PromptContextComposer();
    }

    @Bean
    @ConditionalOnMissingBean
    public ObservedScopeInferenceService observedScopeInferenceService() {
        return new MetadataObservedScopeInferenceService();
    }


    @Bean
    @ConditionalOnMissingBean
    public PromptContextAuthorizationService promptContextAuthorizationService() {
        return new PromptContextAuthorizationService();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityPromptTemplate securityPromptTemplate(
            SecurityEventEnricher securityEventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            ObjectProvider<McpSecurityContextProvider> mcpSecurityContextProvider) {
        return new SecurityPromptTemplate(
                securityEventEnricher,
                tieredStrategyProperties,
                mcpSecurityContextProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityLearningService securityLearningService(
            ObjectProvider<BaselineLearningService> baselineLearningServiceProvider,
            ObjectProvider<SecurityDecisionPostProcessor> postProcessorProvider) {
        return new SecurityLearningService(
                baselineLearningServiceProvider.getIfAvailable(),
                postProcessorProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminOverrideService adminOverrideService(
            SecurityLearningService securityLearningService,
            ZeroTrustActionRepository actionRedisRepository,
            DistributedLockService lockService,
            CentralAuditFacade centralAuditFacade,
            @Nullable DecisionFeedbackForwardingService decisionFeedbackForwardingService,
            @Nullable ThreatOutcomeForwardingService threatOutcomeForwardingService,
            BlockingSignalBroadcaster blockingSignalBroadcaster) {
        return new AdminOverrideService(
                securityLearningService,
                actionRedisRepository,
                lockService,
                centralAuditFacade,
                decisionFeedbackForwardingService,
                threatOutcomeForwardingService,
                blockingSignalBroadcaster
                );
    }

    @Bean
    @ConditionalOnMissingBean
    public CentralAuditFacade centralAuditFacade(
            AuditLogRepository auditLogRepository,
            ApplicationEventPublisher eventPublisher,
            ObjectMapper objectMapper) {
        return new CentralAuditFacade(auditLogRepository, eventPublisher, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuditPersistenceListener auditPersistenceListener(CentralAuditFacade centralAuditFacade) {
        return new AuditPersistenceListener(centralAuditFacade);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuditingHandler auditingHandler(CentralAuditFacade centralAuditFacade) {
        return new AuditingHandler(centralAuditFacade);
    }

    @Bean
    @ConditionalOnMissingBean
    public SoarContextProviderImpl soarContextProviderImpl(SecurityPlaneProperties securityPlaneProperties) {
        return new SoarContextProviderImpl(securityPlaneProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityMonitoringService securityMonitoringService(
            SecurityEventCollector eventCollector) {
        return new SecurityMonitoringService(eventCollector);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityEventProcessor securityEventProcessingOrchestrator(
            List<SecurityEventHandler> handlers) {
        return new SecurityEventProcessor(handlers);
    }

    // === Common beans: work in both standalone and distributed modes ===

    @Bean
    @ConditionalOnMissingBean
    public VectorStoreCacheLayer vectorStoreCacheLayer(
            VectorStore vectorStore,
            TieredStrategyProperties tieredStrategyProperties) {
        return new VectorStoreCacheLayer(vectorStore, tieredStrategyProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({UnifiedLLMOrchestrator.class, UnifiedVectorService.class, BehaviorVectorService.class, BaselineLearningService.class})
    public Layer1ContextualStrategy contextualStrategy(
            UnifiedLLMOrchestrator llmOrchestrator,
            UnifiedVectorService unifiedVectorService,
            SecurityContextDataStore dataStore,
            SecurityEventEnricher securityEventEnricher,
            SecurityPromptTemplate securityPromptTemplate,
            BehaviorVectorService behaviorVectorService,
            BaselineLearningService baselineLearningService,
            SecurityLearningService securityLearningService,
            ObjectProvider<SaasBaselineSeedService> baselineSeedService,
            ObjectProvider<SaasThreatIntelligenceService> threatIntelligenceService,
            ObjectProvider<SaasThreatKnowledgePackService> threatKnowledgePackService,
            ObjectProvider<PromptContextAuditForwardingService> promptContextAuditForwardingService,
            PromptContextAuthorizationService promptContextAuthorizationService,
            TieredStrategyProperties tieredStrategyProperties) {
        return new Layer1ContextualStrategy(
                llmOrchestrator,
                unifiedVectorService,
                dataStore,
                securityEventEnricher,
                securityPromptTemplate,
                behaviorVectorService,
                baselineLearningService,
                securityLearningService,
                baselineSeedService.getIfAvailable(),
                threatIntelligenceService.getIfAvailable(),
                threatKnowledgePackService.getIfAvailable(),
                promptContextAuthorizationService,
                promptContextAuditForwardingService.getIfAvailable(),
                tieredStrategyProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({UnifiedLLMOrchestrator.class, UnifiedVectorService.class, BehaviorVectorService.class, BaselineLearningService.class})
    public Layer2ExpertStrategy expertStrategy(
            UnifiedLLMOrchestrator llmOrchestrator,
            @Autowired(required = false) ApprovalService approvalService,
            SecurityContextDataStore dataStore,
            SecurityEventEnricher securityEventEnricher,
            SecurityPromptTemplate securityPromptTemplate,
            UnifiedVectorService unifiedVectorService,
            BehaviorVectorService behaviorVectorService,
            BaselineLearningService baselineLearningService,
            TieredStrategyProperties tieredStrategyProperties,
            SecurityLearningService securityLearningService,
            ObjectProvider<SaasBaselineSeedService> baselineSeedService,
            ObjectProvider<SaasThreatIntelligenceService> threatIntelligenceService,
            ObjectProvider<SaasThreatKnowledgePackService> threatKnowledgePackService,
            ObjectProvider<PromptContextAuditForwardingService> promptContextAuditForwardingService,
            PromptContextAuthorizationService promptContextAuthorizationService) {
        return new Layer2ExpertStrategy(
                llmOrchestrator,
                approvalService,
                dataStore,
                securityEventEnricher,
                securityPromptTemplate,
                unifiedVectorService,
                behaviorVectorService,
                baselineLearningService,
                tieredStrategyProperties,
                securityLearningService,
                baselineSeedService.getIfAvailable(),
                threatIntelligenceService.getIfAvailable(),
                threatKnowledgePackService.getIfAvailable(),
                promptContextAuthorizationService,
                promptContextAuditForwardingService.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityDecisionPostProcessor securityDecisionPostProcessor(
            SecurityContextDataStore dataStore,
            UnifiedVectorService unifiedVectorService) {
        return new SecurityDecisionPostProcessor(dataStore, unifiedVectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityPlaneAgent securityPlaneAgent(
            SecurityMonitoringService securityMonitor,
            SecurityContextDataStore dataStore,
            CentralAuditFacade centralAuditFacade,
            SecurityEventProcessor processingOrchestrator,
            SecurityPlaneProperties securityPlaneProperties,
            @Qualifier("llmAnalysisExecutor") Executor llmAnalysisExecutor
    ) {
        return new SecurityPlaneAgent(
                securityMonitor, dataStore, centralAuditFacade,
                processingOrchestrator, securityPlaneProperties, llmAnalysisExecutor);
    }

    @Bean
    @ConditionalOnMissingBean
    public SynchronousProtectableDecisionService synchronousProtectableDecisionService(
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            ZeroTrustEventListener zeroTrustEventListener,
            SecurityPlaneAgent securityPlaneAgent,
            ZeroTrustActionRepository actionRepository) {
        return new SynchronousProtectableDecisionService(
                zeroTrustEventPublisher,
                zeroTrustEventListener,
                securityPlaneAgent,
                actionRepository);
    }
    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustExceptionHandler zeroTrustExceptionHandler() {
        return new ZeroTrustExceptionHandler();
    }

    // === Distributed mode: Redis-only repository ===

    @Configuration
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    @ConditionalOnBean(RedisTemplate.class)
    static class DistributedRepositoryConfiguration {

        @Bean
        @ConditionalOnMissingBean(ZeroTrustActionRepository.class)
        public ZeroTrustActionRedisRepository zeroTrustActionRedisRepository(
                RedisTemplate<String, Object> redisTemplate,
                StringRedisTemplate stringRedisTemplate) {
            return new ZeroTrustActionRedisRepository(redisTemplate, stringRedisTemplate);
        }

        @Bean
        @ConditionalOnMissingBean(ProtectableRapidReentryRepository.class)
        public RedisProtectableRapidReentryRepository redisProtectableRapidReentryRepository(
                StringRedisTemplate stringRedisTemplate) {
            return new RedisProtectableRapidReentryRepository(stringRedisTemplate);
        }

        @Bean
        @ConditionalOnMissingBean(ThreatScoreUtil.class)
        public RedisThreatScoreUtil redisThreatScoreUtil(
                RedisTemplate<String, Object> redisTemplate,
                SecurityZeroTrustProperties securityZeroTrustProperties) {
            return new RedisThreatScoreUtil(redisTemplate, securityZeroTrustProperties);
        }

        @Bean
        @ConditionalOnMissingBean(SecurityContextDataStore.class)
        public RedisSecurityContextDataStore redisSecurityContextDataStore(
                RedisTemplate<String, Object> redisTemplate) {
            return new RedisSecurityContextDataStore(redisTemplate);
        }
    }

    // === Standalone mode: In-memory beans ===

    @Configuration
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
    static class StandaloneRepositoryConfiguration {

        @Bean
        @ConditionalOnMissingBean(ZeroTrustActionRepository.class)
        public InMemoryZeroTrustActionRepository inMemoryZeroTrustActionRepository() {
            return new InMemoryZeroTrustActionRepository();
        }

        @Bean
        @ConditionalOnMissingBean(ProtectableRapidReentryRepository.class)
        public InMemoryProtectableRapidReentryRepository inMemoryProtectableRapidReentryRepository() {
            return new InMemoryProtectableRapidReentryRepository();
        }

        @Bean
        @ConditionalOnMissingBean(DistributedLockService.class)
        public InMemoryDistributedLockService inMemoryDistributedLockService() {
            return new InMemoryDistributedLockService();
        }

        @Bean
        @ConditionalOnMissingBean(ThreatScoreUtil.class)
        public InMemoryThreatScoreUtil inMemoryThreatScoreUtil(
                SecurityZeroTrustProperties securityZeroTrustProperties) {
            return new InMemoryThreatScoreUtil(securityZeroTrustProperties);
        }

        @Bean
        @ConditionalOnMissingBean(SecurityContextDataStore.class)
        public InMemorySecurityContextDataStore inMemorySecurityContextDataStore() {
            return new InMemorySecurityContextDataStore();
        }
    }
}





