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

import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
import io.contexa.contexacore.autonomous.store.SessionRecordsIdChangeListener;
import io.contexa.contexacore.autonomous.event.support.EventTimeZoneRegistrar;
import io.contexa.contexacore.autonomous.service.AuthorizationDenialRecorder;
import io.contexa.contexacore.autonomous.service.UnanalysedRequestRecorder;
import io.contexa.contexacore.autonomous.service.LearningPromotionService;
import io.contexa.contexacore.autonomous.service.VerificationLearningService;
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
import io.contexa.contexacore.autonomous.execution.ZeroTrustChallengeFlowStarter;
import io.contexa.contexacore.autonomous.execution.ZeroTrustExceptionHandler;
import io.contexa.contexacore.autonomous.handler.handler.AuditingHandler;
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.repository.*;
import io.contexa.contexacore.autonomous.saas.*;
import io.contexa.contexacore.autonomous.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.service.IForceLogoutService;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDictionary;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptorResolver;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import org.springframework.lang.Nullable;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.autonomous.service.UserAccountDeletionListener;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurger;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import io.contexa.contexacore.autonomous.service.BridgeMirrorUserStatePurgeContributor;
import org.springframework.transaction.PlatformTransactionManager;
import io.contexa.contexacore.autonomous.service.UserStatePurgeContributor;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.service.impl.SoarContextProviderImpl;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.autonomous.store.ExpiringStateStore;
import io.contexa.contexacore.autonomous.store.InMemoryStateSweeper;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.autonomous.tiered.strategy.AbstractTieredStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.utils.InMemoryThreatScoreUtil;
import io.contexa.contexacore.autonomous.utils.RedisThreatScoreUtil;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.baseline.store.InMemoryBaselineDataStore;
import io.contexa.contexacore.autonomous.baseline.store.RedisBaselineDataStore;
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
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.ListableBeanFactory;
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
import org.springframework.context.annotation.Lazy;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
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
import io.contexa.contexacore.autonomous.context.registry.ProtectableResourceContextScanner;
import io.contexa.contexacore.autonomous.context.registry.ResourceContextRegistry;

@AutoConfiguration
@AutoConfigureAfter(name = {
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
        ContexaRagProperties.class
})
public class CoreAutonomousAutoConfiguration {

    public CoreAutonomousAutoConfiguration() {
    }

    /**
     * Binds the trusted proxy settings to the context binding hash so that filters, handlers and
     * repositories resolve the client IP exactly as the security event publisher does. The binding
     * is created eagerly because no other bean depends on it.
     */
    @Bean("contexaClientIpResolutionBinding")
    @Lazy(false)
    @ConditionalOnMissingBean(name = "contexaClientIpResolutionBinding")
    public DisposableBean contexaClientIpResolutionBinding(TieredStrategyProperties tieredStrategyProperties) {
        SessionFingerprintUtil.bindClientIpResolution(tieredStrategyProperties);
        return () -> SessionFingerprintUtil.unbindClientIpResolution(tieredStrategyProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public BaselineLearningService baselineLearningService(
            BaselineDataStore baselineDataStore,
            SecurityZeroTrustProperties zeroTrustProperties,
            ObjectProvider<DistributedLockService> lockServiceProvider) {
        BaselineLearningService service = new BaselineLearningService(baselineDataStore, zeroTrustProperties);
        // The personal and organization baseline updates run under the configured lock service (W5-8).
        service.setLockService(lockServiceProvider.getIfAvailable());
        return service;
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
    public ProtectableResourceContextScanner protectableResourceContextScanner(
            ListableBeanFactory beanFactory, ResourceContextRegistry resourceContextRegistry) {
        return new ProtectableResourceContextScanner(beanFactory, resourceContextRegistry);
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
                slotPlanProvider.getIfAvailable(SecurityDecisionPromptDictionary::slotPlanProvider));
    }

    /** Where the context collectors stage a request's observations until its final decision commits them (W2-7). */
    @Bean
    @ConditionalOnMissingBean
    public ContextObservationRecorder contextObservationRecorder(SecurityContextDataStore dataStore) {
        return new ContextObservationRecorder(dataStore);
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionNarrativeCollector sessionNarrativeCollector(SecurityContextDataStore dataStore,
                                                               ContextObservationRecorder contextObservationRecorder) {
        return new DefaultSessionNarrativeCollector(dataStore, contextObservationRecorder);
    }

    @Bean
    @ConditionalOnMissingBean
    public ProtectableWorkProfileCollector protectableWorkProfileCollector(
            SecurityContextDataStore dataStore, ContextObservationRecorder contextObservationRecorder) {
        return new DefaultProtectableWorkProfileCollector(dataStore, contextObservationRecorder);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleScopeCollector roleScopeCollector(SecurityContextDataStore dataStore,
                                                 ContextObservationRecorder contextObservationRecorder) {
        return new DefaultRoleScopeCollector(dataStore, contextObservationRecorder);
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
            ObjectProvider<PromptRuntimeGovernanceRuleProvider> promptRuntimeGovernanceRuleProvider,
            ObjectProvider<PromptBundleSelector> promptBundleSelector,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        // Without a selector bean the configured bundle runs (contexa.security.tiered.prompt-bundle.active, W3-16).
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                securityEventEnricher,
                tieredStrategyProperties,
                canonicalSecurityContextProvider,
                promptContextComposer,
                promptGovernanceDescriptorResolver.getIfAvailable(PromptGovernanceDescriptorResolver::identity),
                promptRuntimeGovernanceRuleProvider.getIfAvailable(PromptRuntimeGovernanceRuleProvider::none),
                promptBundleSelector.getIfAvailable());
        // W4-4: the system text states the minimum action rules the strategies check, with the host's settings.
        template.setMinimumActionSettings(securityZeroTrustProperties.getMinimumAction().toRules());
        return template;
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
            @Qualifier("securityLearningPostProcessExecutor") ExecutorService securityLearningPostProcessExecutor,
            ObjectProvider<ContextObservationRecorder> contextObservationRecorderProvider) {
        SecurityLearningService service = new SecurityLearningService(
                baselineLearningServiceProvider.getIfAvailable(),
                postProcessorProvider.getIfAvailable(),
                securityLearningPostProcessExecutor);
        // The analysis layers' decision documents are stored once the decision is enforced (W5-3).
        service.setContextObservationRecorder(contextObservationRecorderProvider.getIfAvailable());
        return service;
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
            ObjectProvider<PromptContextAuditRecorder> promptContextAuditRecorder,
            PromptContextAuthorizationService promptContextAuthorizationService,
            ObjectProvider<PipelineOrchestrator> pipelineOrchestrator,
            StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry,
            @Qualifier("layer1RagRetrievalExecutor") ExecutorService layer1RagRetrievalExecutor,
            TieredStrategyProperties tieredStrategyProperties,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ObjectProvider<ModelSelectionStrategy> modelSelectionStrategy) {
        Layer1ContextualStrategy strategy = new Layer1ContextualStrategy(
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
                promptContextAuditRecorder.getIfAvailable(),
                pipelineOrchestrator.getIfAvailable(),
                tieredStrategyProperties,
                structuredOutputCapabilityRegistry,
                layer1RagRetrievalExecutor);
        applyMinimumActionSettings(strategy, securityZeroTrustProperties);
        strategy.setModelSelectionStrategy(modelSelectionStrategy::getIfAvailable);
        return strategy;
    }

    /** The host's minimum-action rule settings (W4-4) for a security decision strategy. */
    private static void applyMinimumActionSettings(AbstractTieredStrategy strategy, SecurityZeroTrustProperties properties) {
        strategy.setMinimumActionSettings(properties.getMinimumAction().toRules(),
                properties.getMinimumAction().getMode().name());
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
            ObjectProvider<PromptContextAuditRecorder> promptContextAuditRecorder,
            PromptContextAuthorizationService promptContextAuthorizationService,
            ObjectProvider<PipelineOrchestrator> pipelineOrchestrator,
            StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ObjectProvider<ModelSelectionStrategy> modelSelectionStrategy) {
        Layer2ExpertStrategy strategy = new Layer2ExpertStrategy(
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
                promptContextAuditRecorder.getIfAvailable(),
                pipelineOrchestrator.getIfAvailable(),
                structuredOutputCapabilityRegistry);
        applyMinimumActionSettings(strategy, securityZeroTrustProperties);
        strategy.setModelSelectionStrategy(modelSelectionStrategy::getIfAvailable);
        return strategy;
    }

    @Bean
    @ConditionalOnBean(UnifiedVectorService.class)
    @ConditionalOnMissingBean
    public SecurityDecisionPostProcessor securityDecisionPostProcessor(
            SecurityContextDataStore dataStore,
            UnifiedVectorService unifiedVectorService,
            ObjectProvider<SecurityZeroTrustProperties> securityZeroTrustProperties) {
        SecurityDecisionPostProcessor postProcessor = new SecurityDecisionPostProcessor(dataStore, unifiedVectorService);
        SecurityZeroTrustProperties properties = securityZeroTrustProperties.getIfAvailable();
        if (properties != null && properties.getBaseline() != null && properties.getBaseline().getPromotion() != null) {
            // The past record of an allowed request the learning promotion holds is stored held (W5-1).
            postProcessor.setLearningPromotionSettings(properties.getBaseline().getPromotion().toPolicy());
        }
        return postProcessor;
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
            ObjectProvider<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterProvider,
            ZeroTrustActionRepository zeroTrustActionRepository,
            ObjectProvider<SecurityDecisionEnforcementHandler> decisionEnforcementHandlerProvider
    ) {
        SecurityPlaneAgent agent = new SecurityPlaneAgent(
                securityMonitor, dataStore, centralAuditFacade,
                processingOrchestrator, securityPlaneProperties, llmAnalysisExecutor);
        agent.setAiSecurityDecisionObservationWriterSupplier(aiSecurityDecisionObservationWriterProvider::getIfAvailable);
        agent.setZeroTrustActionRepository(zeroTrustActionRepository);
        agent.setDecisionEnforcementHandlerSupplier(decisionEnforcementHandlerProvider::getIfAvailable);
        return agent;
    }

    @Bean
    @ConditionalOnMissingBean
    public EventTimeZoneRegistrar eventTimeZoneRegistrar(SecurityPlaneProperties securityPlaneProperties) {
        return new EventTimeZoneRegistrar(securityPlaneProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthorizationDenialRecorder authorizationDenialRecorder(
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            SecurityContextDataStore securityContextDataStore,
            ObjectProvider<RoleScopeCollector> roleScopeCollectorProvider,
            ContextObservationRecorder contextObservationRecorder) {
        return new AuthorizationDenialRecorder(
                zeroTrustEventPublisher, securityContextDataStore, roleScopeCollectorProvider.getIfAvailable(),
                contextObservationRecorder);
    }

    /** Learns, once the user is verified, the request a restriction stopped, at a reduced weight (W5-2). */
    @Bean
    @ConditionalOnMissingBean
    public VerificationLearningService verificationLearningService(
            SecurityContextDataStore securityContextDataStore,
            ObjectProvider<SecurityLearningService> securityLearningService,
            ObjectProvider<ProtectableWorkProfileCollector> protectableWorkProfileCollector,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ObjectProvider<LearningPromotionService> learningPromotionService,
            ObjectProvider<UnifiedVectorService> unifiedVectorService) {
        VerificationLearningService service = new VerificationLearningService(securityContextDataStore,
                securityLearningService.getIfAvailable(), protectableWorkProfileCollector.getIfAvailable(),
                securityZeroTrustProperties);
        service.setLearningPromotionService(learningPromotionService.getIfAvailable());
        // W5-4: a verification or a release writes how the decision ended on the decision's record.
        UnifiedVectorService vectors = unifiedVectorService.getIfAvailable();
        service.setPastRecordQuery(vectors != null ? vectors.pastRecordQuery() : null);
        return service;
    }

    /**
     * Holds back an allowed request whose first-seen values on a sensitive resource no record explains, and learns it
     * once they are seen on other days or verified (W5-1, plan L1).
     */
    @Bean
    @ConditionalOnMissingBean
    public LearningPromotionService learningPromotionService(
            SecurityContextDataStore securityContextDataStore,
            ObjectProvider<SecurityLearningService> securityLearningService,
            ObjectProvider<ProtectableWorkProfileCollector> protectableWorkProfileCollector,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new LearningPromotionService(securityContextDataStore, securityLearningService.getIfAvailable(),
                protectableWorkProfileCollector.getIfAvailable(), securityZeroTrustProperties);
    }

    /** Keeps a request answered by the decision in force, which reaches no analysis, in its session (N-SES-1). */
    @Bean
    @ConditionalOnMissingBean
    public UnanalysedRequestRecorder unanalysedRequestRecorder(
            SessionNarrativeCollector sessionNarrativeCollector,
            ContextObservationRecorder contextObservationRecorder,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustEventPublisher zeroTrustEventPublisher) {
        return new UnanalysedRequestRecorder(sessionNarrativeCollector, contextObservationRecorder,
                securityZeroTrustProperties, zeroTrustEventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionRecordsIdChangeListener sessionRecordsIdChangeListener(
            SecurityContextDataStore securityContextDataStore) {
        return new SessionRecordsIdChangeListener(securityContextDataStore);
    }

    @Bean
    @ConditionalOnMissingBean
    public SynchronousProtectableDecisionService synchronousProtectableDecisionService(
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            ZeroTrustEventListener zeroTrustEventListener,
            SecurityPlaneAgent securityPlaneAgent,
            ZeroTrustActionRepository actionRepository,
            ObjectProvider<UnanalysedRequestRecorder> unanalysedRequestRecorder) {
        SynchronousProtectableDecisionService service = new SynchronousProtectableDecisionService(
                zeroTrustEventPublisher,
                zeroTrustEventListener,
                securityPlaneAgent,
                actionRepository);
        service.setUnanalysedRequestRecorder(unanalysedRequestRecorder.getIfAvailable());
        return service;
    }
    /**
     * The step-up flow of a CHALLENGE decided in the request starts through the identity module's starter (its
     * challenge filter), looked up when the answer is written so the bean order does not matter.
     */
    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustExceptionHandler zeroTrustExceptionHandler(
            ObjectProvider<ZeroTrustChallengeFlowStarter> challengeFlowStarters) {
        return new ZeroTrustExceptionHandler((request, response) -> {
            ZeroTrustChallengeFlowStarter starter = challengeFlowStarters.getIfUnique();
            return starter == null ? Optional.empty() : starter.start(request, response);
        });
    }


    @Configuration
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    @ConditionalOnBean(RedisTemplate.class)
    static class DistributedRepositoryConfiguration {

        @Bean
        @ConditionalOnMissingBean(BaselineDataStore.class)
        public RedisBaselineDataStore baselineDataStore(
                @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate) {
            return new RedisBaselineDataStore(redisTemplate);
        }

        @Bean
        @ConditionalOnMissingBean(ZeroTrustActionRepository.class)
        public ZeroTrustActionRedisRepository zeroTrustActionRedisRepository(
                @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate,
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
                @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate,
                SecurityZeroTrustProperties securityZeroTrustProperties) {
            return new RedisThreatScoreUtil(redisTemplate, securityZeroTrustProperties);
        }

        @Bean
        @ConditionalOnMissingBean(SecurityContextDataStore.class)
        public RedisSecurityContextDataStore redisSecurityContextDataStore(
                @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate,
                ObjectProvider<SecurityPlaneProperties> securityPlaneProperties) {
            RedisSecurityContextDataStore store = new RedisSecurityContextDataStore(redisTemplate);
            SecurityPlaneProperties properties = securityPlaneProperties.getIfAvailable();
            if (properties != null) {
                store.setLoginFailureRetention(Duration.ofMinutes(
                        Math.max(1, properties.getContext().getLoginFailureWindowMinutes())));
            }
            return store;
        }

        @Bean
        @ConditionalOnMissingBean(DistributedLockService.class)
        public RedisDistributedLockService redisDistributedLockService(
                @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate) {
            return new RedisDistributedLockService(redisTemplate);
        }
    }

    @Bean
    @ConditionalOnMissingBean(ZeroTrustActionRepository.class)
      @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
      public InMemoryZeroTrustActionRepository inMemoryZeroTrustActionRepository() {
          return new InMemoryZeroTrustActionRepository();
      }

      @Bean
      @ConditionalOnMissingBean(BaselineDataStore.class)
      @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
      public InMemoryBaselineDataStore baselineDataStore() {
          return new InMemoryBaselineDataStore();
      }

    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean(ProtectableRapidReentryRepository.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
    public InMemoryProtectableRapidReentryRepository inMemoryProtectableRapidReentryRepository() {
        return new InMemoryProtectableRapidReentryRepository();
    }

    @Bean
    @ConditionalOnMissingBean(DistributedLockService.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
    public InMemoryDistributedLockService inMemoryDistributedLockService() {
        return new InMemoryDistributedLockService();
    }

    @Bean
    @ConditionalOnMissingBean(ThreatScoreUtil.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
    public InMemoryThreatScoreUtil inMemoryThreatScoreUtil(
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new InMemoryThreatScoreUtil(securityZeroTrustProperties);
    }

    @Bean
    @ConditionalOnMissingBean(SecurityContextDataStore.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
    public InMemorySecurityContextDataStore inMemorySecurityContextDataStore(
            ObjectProvider<SecurityPlaneProperties> securityPlaneProperties) {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        SecurityPlaneProperties properties = securityPlaneProperties.getIfAvailable();
        if (properties != null) {
            store.setLoginFailureRetention(Duration.ofMinutes(
                    Math.max(1, properties.getContext().getLoginFailureWindowMinutes())));
        }
        return store;
    }

    @Bean
    @ConditionalOnMissingBean
    public UserEngineStatePurger userEngineStatePurger(
            ZeroTrustActionRepository zeroTrustActionRepository,
            ObjectProvider<BlockingSignalBroadcaster> blockingSignalBroadcaster,
            ObjectProvider<BlockMfaStateStore> blockMfaStateStore,
            ObjectProvider<BaselineDataStore> baselineDataStore,
            ObjectProvider<SecurityContextDataStore> securityContextDataStore,
            ObjectProvider<ColdPathEventProcessor> coldPathEventProcessor,
            ObjectProvider<VectorStore> vectorStore,
            ObjectProvider<IForceLogoutService> forceLogoutService,
            ObjectProvider<UserStatePurgeContributor> contributors,
            ObjectProvider<VectorStoreCacheLayer> vectorStoreCacheLayer) {
        UserEngineStatePurger purger = new UserEngineStatePurger(
                zeroTrustActionRepository,
                blockingSignalBroadcaster.getIfAvailable(),
                blockMfaStateStore.getIfAvailable(),
                baselineDataStore.getIfAvailable(),
                securityContextDataStore.getIfAvailable(),
                coldPathEventProcessor.getIfAvailable(),
                vectorStore.getIfUnique(),
                forceLogoutService.getIfAvailable(),
                contributors.orderedStream().toList());
        purger.setVectorStoreCacheLayer(vectorStoreCacheLayer.getIfAvailable());
        return purger;
    }

    /** Removes the security bridge's mirror users of a deleted account; skips itself without the user tables. */
    @Bean
    public UserStatePurgeContributor bridgeMirrorUserStatePurgeContributor(
            ObjectProvider<UserRepository> userRepository,
            ObjectProvider<BridgeUserProfileRepository> bridgeUserProfileRepository,
            ObjectProvider<UserRolePermissionRepository> userRolePermissionRepository,
            @Qualifier("contexaTransactionManager") ObjectProvider<PlatformTransactionManager> contexaTransactionManager) {
        return new BridgeMirrorUserStatePurgeContributor(userRepository, bridgeUserProfileRepository,
                userRolePermissionRepository, contexaTransactionManager);
    }

    @Bean
    @ConditionalOnMissingBean
    public UserAccountDeletionListener userAccountDeletionListener(UserEngineStatePurger userEngineStatePurger) {
        return new UserAccountDeletionListener(userEngineStatePurger);
    }

    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean
    public InMemoryStateSweeper inMemoryStateSweeper(ObjectProvider<ExpiringStateStore> expiringStateStores) {
        return new InMemoryStateSweeper(
                () -> expiringStateStores.orderedStream().toList(), InMemoryStateSweeper.DEFAULT_INTERVAL);
    }
}





