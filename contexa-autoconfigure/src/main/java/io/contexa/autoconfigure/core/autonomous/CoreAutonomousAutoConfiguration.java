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
import io.contexa.contexacore.autonomous.execution.DelegatedExecutionFingerprintService;
import io.contexa.contexacore.autonomous.execution.ZeroTrustExceptionHandler;
import io.contexa.contexacore.autonomous.handler.handler.AuditingHandler;
import io.contexa.contexacore.autonomous.repository.*;
import io.contexa.contexacore.autonomous.saas.*;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptorResolver;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
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
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.utils.InMemoryThreatScoreUtil;
import io.contexa.contexacore.autonomous.utils.RedisThreatScoreUtil;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.infra.lock.InMemoryDistributedLockService;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import io.contexa.contexacore.autonomous.context.collector.DefaultProtectableWorkProfileCollector;
import io.contexa.contexacore.autonomous.context.collector.DefaultRoleScopeCollector;
import io.contexa.contexacore.autonomous.context.collector.DefaultSessionNarrativeCollector;
import io.contexa.contexacore.autonomous.context.collector.ProtectableWorkProfileCollector;
import io.contexa.contexacore.autonomous.context.collector.RoleScopeCollector;
import io.contexa.contexacore.autonomous.context.collector.SessionNarrativeCollector;
import io.contexa.contexacore.autonomous.context.enricher.AuthenticationContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.AuthorizationSnapshotProvider;
import io.contexa.contexacore.autonomous.context.enricher.DelegationContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.FrictionContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.OrganizationContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.PeerCohortContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.ReasoningMemoryContextProvider;
import io.contexa.contexacore.autonomous.context.inference.ContextCoverageEvaluator;
import io.contexa.contexacore.autonomous.context.inference.MetadataObservedScopeInferenceService;
import io.contexa.contexacore.autonomous.context.inference.ObservedScopeInferenceService;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleProvider;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlotPlanProvider;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlotRenderer;
import io.contexa.contexacore.autonomous.context.registry.InMemoryResourceContextRegistry;
import io.contexa.contexacore.autonomous.context.registry.ResourceContextRegistry;

@AutoConfiguration
@AutoConfigureAfter(name = {
        "io.contexa.autoconfigure.core.hcad.CoreHCADAutoConfiguration",
        "io.contexa.autoconfigure.core.llm.CoreLLMTieredAutoConfiguration",
        "io.contexa.autoconfigure.core.rag.CoreRAGAutoConfiguration",
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
        "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration"
})
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
    public DelegatedExecutionFingerprintService delegatedExecutionFingerprintService() {
        return new DelegatedExecutionFingerprintService();
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
            ObjectProvider<PeerCohortContextProvider> peerCohortContextProviders,
            ObjectProvider<FrictionContextProvider> frictionContextProviders,
            ObjectProvider<ReasoningMemoryContextProvider> reasoningMemoryContextProviders,
            ObjectProvider<SessionNarrativeCollector> sessionNarrativeCollector,
            ObjectProvider<ProtectableWorkProfileCollector> protectableWorkProfileCollector,
            ObjectProvider<RoleScopeCollector> roleScopeCollector,
            ObjectProvider<ObservedScopeInferenceService> observedScopeInferenceService) {
        return new DefaultCanonicalSecurityContextProvider(
                resourceContextRegistry,
                contextCoverageEvaluator,
                authenticationContextProviders.orderedStream().toList(),
                authorizationSnapshotProviders.orderedStream().toList(),
                organizationContextProviders.orderedStream().toList(),
                delegationContextProviders.orderedStream().toList(),
                peerCohortContextProviders.orderedStream().toList(),
                frictionContextProviders.orderedStream().toList(),
                reasoningMemoryContextProviders.orderedStream().toList(),
                observedScopeInferenceService.getIfAvailable(),
                sessionNarrativeCollector.getIfAvailable(),
                protectableWorkProfileCollector.getIfAvailable(),
                roleScopeCollector.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public PromptContextComposer promptContextComposer(ObjectProvider<PromptSlotPlanProvider> slotPlanProvider) {
        return new PromptContextComposer(
                new PromptSlotRenderer(),
                slotPlanProvider.getIfAvailable(PromptSlotPlanProvider::unscoped));
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionNarrativeCollector sessionNarrativeCollector(SecurityContextDataStore dataStore) {
        return new DefaultSessionNarrativeCollector(dataStore);
    }

    @Bean
    @ConditionalOnMissingBean
    public ProtectableWorkProfileCollector protectableWorkProfileCollector(SecurityContextDataStore dataStore) {
        return new DefaultProtectableWorkProfileCollector(dataStore);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleScopeCollector roleScopeCollector(SecurityContextDataStore dataStore) {
        return new DefaultRoleScopeCollector(dataStore);
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
    public SecurityDecisionStandardPromptTemplate securityDecisionStandardPromptTemplate(
            SecurityEventEnricher securityEventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            CanonicalSecurityContextProvider canonicalSecurityContextProvider,
            PromptContextComposer promptContextComposer,
            ObjectProvider<PromptGovernanceDescriptorResolver> promptGovernanceDescriptorResolver,
            ObjectProvider<PromptRuntimeGovernanceRuleProvider> promptRuntimeGovernanceRuleProvider) {
        return new SecurityDecisionStandardPromptTemplate(
                securityEventEnricher,
                tieredStrategyProperties,
                canonicalSecurityContextProvider,
                promptContextComposer,
                promptGovernanceDescriptorResolver.getIfAvailable(PromptGovernanceDescriptorResolver::identity),
                promptRuntimeGovernanceRuleProvider.getIfAvailable(PromptRuntimeGovernanceRuleProvider::none));
    }

    @Bean(destroyMethod = "shutdown")
    @ConditionalOnMissingBean(name = "securityLearningPostProcessExecutor")
    public ExecutorService securityLearningPostProcessExecutor() {
        return new ThreadPoolExecutor(
                2,
                4,
                60L,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(1000),
                namedThreadFactory("Security-Learning-"),
                new ThreadPoolExecutor.CallerRunsPolicy());
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityLearningService securityLearningService(
            ObjectProvider<BaselineLearningService> baselineLearningServiceProvider,
            ObjectProvider<SecurityDecisionPostProcessor> postProcessorProvider,
            @Qualifier("securityLearningPostProcessExecutor") ExecutorService securityLearningPostProcessExecutor) {
        return new SecurityLearningService(
                baselineLearningServiceProvider.getIfAvailable(),
                postProcessorProvider.getIfAvailable(),
                securityLearningPostProcessExecutor);
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
            SecurityEventCollector eventCollector,
            SecurityPlaneProperties securityPlaneProperties) {
        return new SecurityMonitoringService(eventCollector, securityPlaneProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(VectorStore.class)
    public VectorStoreCacheLayer vectorStoreCacheLayer(
            VectorStore vectorStore,
            TieredStrategyProperties tieredStrategyProperties) {
        return new VectorStoreCacheLayer(vectorStore, tieredStrategyProperties);
    }

    @Bean(destroyMethod = "shutdown")
    @ConditionalOnMissingBean(name = "layer1RagRetrievalExecutor")
    public ExecutorService layer1RagRetrievalExecutor() {
        return new ThreadPoolExecutor(
                2,
                8,
                60L,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(500),
                namedThreadFactory("Layer1-RAG-"),
                new ThreadPoolExecutor.AbortPolicy());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({UnifiedLLMOrchestrator.class, UnifiedVectorService.class, BehaviorVectorService.class, BaselineLearningService.class})
    public Layer1ContextualStrategy contextualStrategy(
            UnifiedVectorService unifiedVectorService,
            SecurityContextDataStore dataStore,
            SecurityEventEnricher securityEventEnricher,
            SecurityDecisionStandardPromptTemplate securityDecisionStandardPromptTemplate,
            BehaviorVectorService behaviorVectorService,
            BaselineLearningService baselineLearningService,
            SecurityLearningService securityLearningService,
            ObjectProvider<SaasBaselineSeedService> baselineSeedService,
            ObjectProvider<SaasThreatIntelligenceService> threatIntelligenceService,
            ObjectProvider<SaasThreatKnowledgePackService> threatKnowledgePackService,
            ObjectProvider<SaasDetectionStrategyPackService> detectionStrategyPackService,
            ObjectProvider<PromptContextAuditForwardingService> promptContextAuditForwardingService,
            PromptContextAuthorizationService promptContextAuthorizationService,
            ObjectProvider<PipelineOrchestrator> pipelineOrchestrator,
            StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry,
            @Qualifier("layer1RagRetrievalExecutor") ExecutorService layer1RagRetrievalExecutor,
            TieredStrategyProperties tieredStrategyProperties) {
        return new Layer1ContextualStrategy(
                unifiedVectorService,
                dataStore,
                securityEventEnricher,
                securityDecisionStandardPromptTemplate,
                behaviorVectorService,
                baselineLearningService,
                securityLearningService,
                baselineSeedService.getIfAvailable(),
                threatIntelligenceService.getIfAvailable(),
                threatKnowledgePackService.getIfAvailable(),
                detectionStrategyPackService.getIfAvailable(),
                promptContextAuthorizationService,
                promptContextAuditForwardingService.getIfAvailable(),
                pipelineOrchestrator.getIfAvailable(),
                tieredStrategyProperties,
                structuredOutputCapabilityRegistry,
                layer1RagRetrievalExecutor);
    }

    private ThreadFactory namedThreadFactory(String prefix) {
        AtomicInteger threadNumber = new AtomicInteger(1);
        return runnable -> {
            Thread thread = new Thread(runnable);
            thread.setName(prefix + threadNumber.getAndIncrement());
            return thread;
        };
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({UnifiedLLMOrchestrator.class, UnifiedVectorService.class, BehaviorVectorService.class, BaselineLearningService.class})
    public Layer2ExpertStrategy expertStrategy(
            @Autowired(required = false) ApprovalService approvalService,
            SecurityContextDataStore dataStore,
            SecurityEventEnricher securityEventEnricher,
            SecurityDecisionStandardPromptTemplate securityDecisionStandardPromptTemplate,
            UnifiedVectorService unifiedVectorService,
            BehaviorVectorService behaviorVectorService,
            BaselineLearningService baselineLearningService,
            TieredStrategyProperties tieredStrategyProperties,
            SecurityLearningService securityLearningService,
            ObjectProvider<SaasBaselineSeedService> baselineSeedService,
            ObjectProvider<SaasThreatIntelligenceService> threatIntelligenceService,
            ObjectProvider<SaasThreatKnowledgePackService> threatKnowledgePackService,
            ObjectProvider<SaasDetectionStrategyPackService> detectionStrategyPackService,
            ObjectProvider<PromptContextAuditForwardingService> promptContextAuditForwardingService,
            PromptContextAuthorizationService promptContextAuthorizationService,
            ObjectProvider<PipelineOrchestrator> pipelineOrchestrator,
            StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry) {
        return new Layer2ExpertStrategy(
                approvalService,
                dataStore,
                securityEventEnricher,
                securityDecisionStandardPromptTemplate,
                unifiedVectorService,
                behaviorVectorService,
                baselineLearningService,
                tieredStrategyProperties,
                securityLearningService,
                baselineSeedService.getIfAvailable(),
                threatIntelligenceService.getIfAvailable(),
                threatKnowledgePackService.getIfAvailable(),
                detectionStrategyPackService.getIfAvailable(),
                promptContextAuthorizationService,
                promptContextAuditForwardingService.getIfAvailable(),
                pipelineOrchestrator.getIfAvailable(),
                structuredOutputCapabilityRegistry);
    }

    @Bean
    @ConditionalOnBean(UnifiedVectorService.class)
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
            @Qualifier("llmAnalysisExecutor") Executor llmAnalysisExecutor,
            ObjectProvider<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterProvider
    ) {
        SecurityPlaneAgent agent = new SecurityPlaneAgent(
                securityMonitor, dataStore, centralAuditFacade,
                processingOrchestrator, securityPlaneProperties, llmAnalysisExecutor);
        agent.setAiSecurityDecisionObservationWriterSupplier(aiSecurityDecisionObservationWriterProvider::getIfAvailable);
        return agent;
    }

    @Bean
    @ConditionalOnMissingBean
    public SynchronousProtectableDecisionService synchronousProtectableDecisionService(
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            ZeroTrustEventListener zeroTrustEventListener,
            SecurityPlaneAgent securityPlaneAgent,
            ZeroTrustActionRepository actionRepository,
            ObjectProvider<AnalysisTriggerStateRepository> analysisTriggerStateRepositoryProvider,
            ObjectProvider<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterProvider) {
        return new SynchronousProtectableDecisionService(
                zeroTrustEventPublisher,
                zeroTrustEventListener,
                securityPlaneAgent,
                actionRepository,
                analysisTriggerStateRepositoryProvider.getIfAvailable(),
                aiSecurityDecisionObservationWriterProvider::getIfAvailable);
    }
    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustExceptionHandler zeroTrustExceptionHandler() {
        return new ZeroTrustExceptionHandler();
    }


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

        @Bean
        @ConditionalOnMissingBean(DistributedLockService.class)
        public RedisDistributedLockService redisDistributedLockService(
                RedisTemplate<String, Object> redisTemplate) {
            return new RedisDistributedLockService(redisTemplate);
        }
    }

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





