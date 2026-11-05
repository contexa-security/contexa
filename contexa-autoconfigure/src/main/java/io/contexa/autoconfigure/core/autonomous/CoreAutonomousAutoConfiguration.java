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

import io.contexa.contexacore.autonomous.agent.AgentLearningControl;
import io.contexa.contexacore.autonomous.agent.DelegationPurgeContributor;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import io.contexa.contexacore.autonomous.agent.RegistryDelegationRecordLookup;
import io.contexa.contexacore.autonomous.company.CompanyRecordStore;
import io.contexa.contexacore.autonomous.company.CompanyRecordsContextProvider;
import io.contexa.contexacore.autonomous.company.CompanyRecordsPurgeContributor;
import io.contexa.contexacore.autonomous.company.InMemoryCompanyRecordStore;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
import io.contexa.contexacore.autonomous.store.SessionRecordsIdChangeListener;
import io.contexa.contexacore.autonomous.event.support.EventTimeZoneRegistrar;
import io.contexa.contexacore.autonomous.service.AuthorizationDenialRecorder;
import io.contexa.contexacore.autonomous.service.UnanalysedRequestRecorder;
import io.contexa.contexacore.autonomous.service.LearningPromotionService;
import io.contexa.contexacore.autonomous.service.LearningStoreRejectionPolicy;
import io.contexa.contexacore.autonomous.service.VerificationLearningService;
import io.contexa.autoconfigure.core.infra.StandaloneLearningStateWarning;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.SecurityEventProcessor;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacommon.security.bridge.runtime.RequestPathDatabaseGuard;
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
import io.contexa.contexacore.autonomous.service.DeletedAccountWriteFence;
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
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import io.contexa.contexacore.autonomous.context.inference.ObjectiveDriftEvaluator;
import io.contexa.contexacore.autonomous.execution.ObjectiveContractSource;
import io.contexa.contexacore.autonomous.execution.ObjectiveResourceCompatibilityCatalog;
import java.util.ArrayList;
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
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexacore.autonomous.agent.RegistryAgentClientDirectory;
import io.contexa.contexacore.autonomous.agent.AgentRegistryRecorder;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexacore.autonomous.context.enricher.AuthenticationContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.AuthorizationSnapshotProvider;
import io.contexa.contexacore.autonomous.context.enricher.DelegationContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.DelegationRecordLookup;
import io.contexa.contexacore.autonomous.context.enricher.FrictionContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.OrganizationContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.PeerCohortContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.ReasoningMemoryContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.RecordedDelegationContextProvider;
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
import io.contexa.contexacore.properties.EvidenceSigningProperties;
import io.contexa.contexacore.verification.evidence.EvidenceSigner;
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import io.contexa.contexacore.autonomous.agent.AgentAllowReuse;
import io.contexa.contexacore.autonomous.agent.AgentDecisionFlights;
import io.contexa.contexacore.autonomous.service.QueuedAgentEventRecheck;

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
        ContexaRagProperties.class,
        EvidenceSigningProperties.class
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

    /**
     * Tells the decision store what a stored ESCALATE ends as, whichever store the application runs on: one it declares
     * itself as well as the built-in ones. The binding is created eagerly because no other bean depends on it.
     */
    @Bean("contexaEscalateTerminalActionBinding")
    @Lazy(false)
    @ConditionalOnMissingBean(name = "contexaEscalateTerminalActionBinding")
    public SmartInitializingSingleton contexaEscalateTerminalActionBinding(
            ObjectProvider<ZeroTrustActionRepository> actionRepository,
            TieredStrategyProperties tieredStrategyProperties) {
        return () -> actionRepository.ifAvailable(repository -> repository.setEscalateTerminalAction(
                tieredStrategyProperties.getLayer2().escalateTerminalAction()));
    }

    @Bean(name = "contexaBaselineLearningService")
    @ConditionalOnMissingBean
    public BaselineLearningService baselineLearningService(
            BaselineDataStore contexaBaselineDataStore,
            SecurityZeroTrustProperties zeroTrustProperties,
            ObjectProvider<DistributedLockService> lockServiceProvider,
            ObjectProvider<SecurityContextDataStore> contextDataStoreProvider) {
        BaselineLearningService service = new BaselineLearningService(contexaBaselineDataStore, zeroTrustProperties);
        // The personal and organization baseline updates run under the configured lock service (W5-8).
        service.setLockService(lockServiceProvider.getIfAvailable());
        // docs/agent A3-8: a quarantined agent's baseline is neither learned nor read.
        SecurityContextDataStore contextDataStore = contextDataStoreProvider.getIfAvailable();
        if (contextDataStore != null) {
            service.setLearningQuarantine(subject -> AgentLearningControl.learningQuarantined(contextDataStore,
                    subject));
        }
        return service;
    }

    @Bean(name = "contexaSecurityEventEnricher")
    @ConditionalOnMissingBean
    public SecurityEventEnricher securityEventEnricher() {
        return new SecurityEventEnricher();
    }

    @Bean(name = "contexaDelegatedExecutionFingerprintService")
    @ConditionalOnMissingBean
    public DelegatedExecutionFingerprintService delegatedExecutionFingerprintService() {
        return new DelegatedExecutionFingerprintService();
    }

    @Bean(name = "contexaResourceContextRegistry")
    @ConditionalOnMissingBean
    public ResourceContextRegistry resourceContextRegistry() {
        return new InMemoryResourceContextRegistry();
    }

    @Bean(name = "contexaProtectableResourceContextScanner")
    @ConditionalOnMissingBean
    public ProtectableResourceContextScanner protectableResourceContextScanner(
            ListableBeanFactory beanFactory, ResourceContextRegistry contexaResourceContextRegistry) {
        return new ProtectableResourceContextScanner(beanFactory, contexaResourceContextRegistry);
    }

    @Bean(name = "contexaContextCoverageEvaluator")
    @ConditionalOnMissingBean
    public ContextCoverageEvaluator contextCoverageEvaluator() {
        return new ContextCoverageEvaluator();
    }

    /**
     * docs/agent A3-8: an operator's quarantine, release and removal of what an agent, or a delegation, learned. The
     * decision records are reached through the past record lookup of the vector store when there is one.
     */
    @Bean(name = "contexaAgentLearningControl")
    @ConditionalOnMissingBean
    public AgentLearningControl agentLearningControl(ObjectProvider<SecurityContextDataStore> securityContextDataStore,
                                                     ObjectProvider<BaselineDataStore> baselineDataStoreProvider,
                                                     ObjectProvider<UnifiedVectorService> unifiedVectorServiceProvider) {
        return new AgentLearningControl(securityContextDataStore.getIfAvailable(), baselineDataStoreProvider.getIfAvailable(),
                () -> {
                    UnifiedVectorService vectors = unifiedVectorServiceProvider.getIfAvailable();
                    return vectors != null ? vectors.pastRecordQuery() : null;
                });
    }

    /** A1-6: the agents Contexa knows; the database registry of the IAM module replaces this one when present. */
    @Bean(name = "contexaDefaultAgentRegistry")
    @ConditionalOnMissingBean(AgentRegistry.class)
    public AgentRegistry defaultAgentRegistry() {
        return new InMemoryAgentRegistry();
    }

    /**
     * A1-2: the approved agents, by the client their tokens are issued to. The resource server admits a client's own
     * token without a user account only for these, and the delegation stamp reads such a token as the agent's.
     */
    @Bean(name = "contexaAgentClientDirectory")
    @ConditionalOnMissingBean(AgentClientDirectory.class)
    public AgentClientDirectory agentClientDirectory(AgentRegistry contexaAgentRegistry,
                                                     ObjectProvider<RequestPathDatabaseGuard> contexaRequestPathDatabaseGuard) {
        return new RegistryAgentClientDirectory(contexaAgentRegistry, contexaRequestPathDatabaseGuard.getIfAvailable(RequestPathDatabaseGuard::new));
    }

    /** A1-6: every agent request reaches the registry. */
    @Bean(name = "contexaAgentRegistryRecorder")
    @ConditionalOnMissingBean
    public AgentRegistryRecorder agentRegistryRecorder(AgentRegistry contexaAgentRegistry,
                                                       SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new AgentRegistryRecorder(contexaAgentRegistry,
                securityZeroTrustProperties.getAgent().getRegistryWriteInterval());
    }

    /**
     * docs/agent OC-1: the delegations Contexa keeps; the database registry of the IAM module replaces this one when
     * present.
     */
    @Bean(name = "contexaDefaultDelegationRegistry")
    @ConditionalOnMissingBean(DelegationRegistry.class)
    public DelegationRegistry defaultDelegationRegistry(SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new InMemoryDelegationRegistry(securityZeroTrustProperties.getAgent().getDelegationMaxValidity(), null);
    }

    /**
     * docs/agent OC-1: agent requests are decided with the delegations Contexa keeps; an application that keeps them in
     * its own system declares its own lookup instead.
     */
    @Bean(name = "contexaDelegationRecordLookup")
    @ConditionalOnMissingBean(DelegationRecordLookup.class)
    public DelegationRecordLookup delegationRecordLookup(DelegationRegistry contexaDelegationRegistry) {
        return new RegistryDelegationRecordLookup(contexaDelegationRegistry);
    }

    /** docs/agent OC-1: a deleted account's delegations go with it. */
    @Bean(name = "contexaDelegationPurgeContributor")
    @ConditionalOnMissingBean(DelegationPurgeContributor.class)
    public DelegationPurgeContributor delegationPurgeContributor(DelegationRegistry contexaDelegationRegistry) {
        return new DelegationPurgeContributor(contexaDelegationRegistry);
    }

    /**
     * docs/agent OC-2: the company records Contexa keeps; the database store of the IAM module replaces this one when
     * present, and an application whose records live elsewhere declares its own.
     */
    @Bean(name = "contexaDefaultCompanyRecordStore")
    @ConditionalOnMissingBean(CompanyRecordStore.class)
    public CompanyRecordStore defaultCompanyRecordStore() {
        return new InMemoryCompanyRecordStore();
    }

    /**
     * docs/agent OC-2: every request a company rule covers is judged with the company records of the person who answers
     * for it; an application's own friction providers run beside it.
     */
    @Bean(name = "contexaCompanyRecordsContextProvider")
    @ConditionalOnMissingBean(CompanyRecordsContextProvider.class)
    public CompanyRecordsContextProvider companyRecordsContextProvider(CompanyRecordStore contexaCompanyRecordStore) {
        return new CompanyRecordsContextProvider(contexaCompanyRecordStore);
    }

    /** docs/agent OC-2: a deleted account's company records go with it. */
    @Bean(name = "contexaCompanyRecordsPurgeContributor")
    @ConditionalOnMissingBean(CompanyRecordsPurgeContributor.class)
    public CompanyRecordsPurgeContributor companyRecordsPurgeContributor(CompanyRecordStore contexaCompanyRecordStore) {
        return new CompanyRecordsPurgeContributor(contexaCompanyRecordStore);
    }

    /** A1-4, OC-1: the delegation record reaches every agent request. */
    @Bean(name = "contexaRecordedDelegationContextProvider")
    @ConditionalOnMissingBean(RecordedDelegationContextProvider.class)
    public RecordedDelegationContextProvider recordedDelegationContextProvider(DelegationRecordLookup contexaDelegationRecordLookup) {
        return new RecordedDelegationContextProvider(contexaDelegationRecordLookup);
    }

    @Bean(name = "contexaCanonicalSecurityContextProvider")
    @ConditionalOnMissingBean
    public CanonicalSecurityContextProvider canonicalSecurityContextProvider(
            ResourceContextRegistry contexaResourceContextRegistry,
            ContextCoverageEvaluator contexaContextCoverageEvaluator,
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
            ObjectProvider<ObservedScopeInferenceService> observedScopeInferenceService,
            ObjectProvider<ObjectiveResourceCompatibilityCatalog> objectiveCatalog) {
        DefaultCanonicalSecurityContextProvider provider = new DefaultCanonicalSecurityContextProvider(
                contexaResourceContextRegistry,
                contexaContextCoverageEvaluator,
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
        objectiveCatalog.ifAvailable(catalog -> provider.setObjectiveDriftEvaluator(new ObjectiveDriftEvaluator(catalog)));
        return provider;
    }

    /**
     * A2-1: the objective contracts delegations are compared with: Contexa's own, the ones the application writes in
     * {@code contexa.security.zerotrust.agent.objective-contracts} and the ones its {@link ObjectiveContractSource} beans
     * declare (in that order, a later contract of the same family taking the earlier one's place).
     */
    @Bean(name = "contexaObjectiveResourceCompatibilityCatalog")
    @ConditionalOnMissingBean
    public ObjectiveResourceCompatibilityCatalog objectiveResourceCompatibilityCatalog(
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ObjectProvider<ObjectiveContractSource> objectiveContractSources) {
        List<ObjectiveResourceCompatibilityCatalog.ObjectiveContractDefinition> contracts =
                new ArrayList<>(securityZeroTrustProperties.getAgent().objectiveContractDefinitions());
        objectiveContractSources.orderedStream().forEach(source -> {
            if (source.objectiveContracts() != null) {
                contracts.addAll(source.objectiveContracts());
            }
        });
        return new ObjectiveResourceCompatibilityCatalog(contracts);
    }

    @Bean(name = "contexaPromptContextComposer")
    @ConditionalOnMissingBean
    public PromptContextComposer promptContextComposer(ObjectProvider<PromptSlotPlanProvider> slotPlanProvider) {
        return new PromptContextComposer(
                new PromptSlotRenderer(),
                slotPlanProvider.getIfAvailable(SecurityDecisionPromptDictionary::slotPlanProvider));
    }

    /** Where the context collectors stage a request's observations until its final decision commits them (W2-7). */
    @Bean(name = "contexaContextObservationRecorder")
    @ConditionalOnMissingBean
    public ContextObservationRecorder contextObservationRecorder(SecurityContextDataStore dataStore) {
        return new ContextObservationRecorder(dataStore);
    }

    @Bean(name = "contexaSessionNarrativeCollector")
    @ConditionalOnMissingBean
    public SessionNarrativeCollector sessionNarrativeCollector(SecurityContextDataStore dataStore,
                                                               ContextObservationRecorder contexaContextObservationRecorder) {
        return new DefaultSessionNarrativeCollector(dataStore, contexaContextObservationRecorder);
    }

    @Bean(name = "contexaProtectableWorkProfileCollector")
    @ConditionalOnMissingBean
    public ProtectableWorkProfileCollector protectableWorkProfileCollector(
            SecurityContextDataStore dataStore, ContextObservationRecorder contexaContextObservationRecorder) {
        return new DefaultProtectableWorkProfileCollector(dataStore, contexaContextObservationRecorder);
    }

    @Bean(name = "contexaRoleScopeCollector")
    @ConditionalOnMissingBean
    public RoleScopeCollector roleScopeCollector(SecurityContextDataStore dataStore,
                                                 ContextObservationRecorder contexaContextObservationRecorder) {
        return new DefaultRoleScopeCollector(dataStore, contexaContextObservationRecorder);
    }

    @Bean(name = "contexaObservedScopeInferenceService")
    @ConditionalOnMissingBean
    public ObservedScopeInferenceService observedScopeInferenceService() {
        return new MetadataObservedScopeInferenceService();
    }


    @Bean(name = "contexaPromptContextAuthorizationService")
    @ConditionalOnMissingBean
    public PromptContextAuthorizationService promptContextAuthorizationService() {
        return new PromptContextAuthorizationService();
    }

    @Bean(name = "contexaSecurityDecisionStandardPromptTemplate")
    @ConditionalOnMissingBean
    public SecurityDecisionStandardPromptTemplate securityDecisionStandardPromptTemplate(
            SecurityEventEnricher contexaSecurityEventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            CanonicalSecurityContextProvider contexaCanonicalSecurityContextProvider,
            PromptContextComposer contexaPromptContextComposer,
            ObjectProvider<PromptGovernanceDescriptorResolver> promptGovernanceDescriptorResolver,
            ObjectProvider<PromptRuntimeGovernanceRuleProvider> promptRuntimeGovernanceRuleProvider,
            ObjectProvider<PromptBundleSelector> promptBundleSelector,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        // Without a selector bean the configured bundle runs (contexa.security.tiered.prompt-bundle.active, W3-16).
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                contexaSecurityEventEnricher,
                tieredStrategyProperties,
                contexaCanonicalSecurityContextProvider,
                contexaPromptContextComposer,
                promptGovernanceDescriptorResolver.getIfAvailable(PromptGovernanceDescriptorResolver::identity),
                promptRuntimeGovernanceRuleProvider.getIfAvailable(PromptRuntimeGovernanceRuleProvider::none),
                promptBundleSelector.getIfAvailable());
        // W4-4: the system text states the minimum action rules the strategies check, with the host's settings.
        template.setMinimumActionSettings(securityZeroTrustProperties.getMinimumAction().toRules());
        return template;
    }

    /**
     * The executor of the learning writes. With no room, a decision document store the enforcement hands over under the
     * request's lock is left to the vector store retry (QF-25 b, R12); every other task runs on the caller as before.
     */
    @Bean(name = "contexaSecurityLearningPostProcessExecutor", destroyMethod = "shutdown", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaSecurityLearningPostProcessExecutor")
    public ExecutorService securityLearningPostProcessExecutor() {
        return new ThreadPoolExecutor(
                2,
                4,
                60L,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(1000),
                namedThreadFactory("Security-Learning-"),
                new LearningStoreRejectionPolicy());
    }

    @Bean(name = "contexaSecurityLearningService")
    @ConditionalOnMissingBean
    public SecurityLearningService securityLearningService(
            ObjectProvider<BaselineLearningService> baselineLearningServiceProvider,
            ObjectProvider<SecurityDecisionPostProcessor> postProcessorProvider,
            @Qualifier("contexaSecurityLearningPostProcessExecutor") ExecutorService contexaSecurityLearningPostProcessExecutor,
            ObjectProvider<ContextObservationRecorder> contextObservationRecorderProvider,
            ObjectProvider<DeletedAccountWriteFence> deletedAccountWriteFence) {
        SecurityLearningService service = new SecurityLearningService(
                baselineLearningServiceProvider.getIfAvailable(),
                postProcessorProvider.getIfAvailable(),
                contexaSecurityLearningPostProcessExecutor);
        // The analysis layers' decision documents are stored once the decision is enforced (W5-3).
        service.setContextObservationRecorder(contextObservationRecorderProvider.getIfAvailable());
        // Q-15: the late writes of a request whose account was deleted after it was taken in are discarded.
        service.setDeletedAccountWriteFence(deletedAccountWriteFence.getIfAvailable());
        return service;
    }
@Bean(name = "contexaAdminOverrideService")
    @ConditionalOnMissingBean
    public AdminOverrideService adminOverrideService(
            SecurityLearningService contexaSecurityLearningService,
            ZeroTrustActionRepository actionRedisRepository,
            DistributedLockService lockService,
            CentralAuditFacade contexaCentralAuditFacade,
            @Nullable DecisionFeedbackForwardingService decisionFeedbackForwardingService,
            @Nullable ThreatOutcomeForwardingService threatOutcomeForwardingService,
            BlockingSignalBroadcaster blockingSignalBroadcaster) {
        return new AdminOverrideService(
                contexaSecurityLearningService,
                actionRedisRepository,
                lockService,
                contexaCentralAuditFacade,
                decisionFeedbackForwardingService,
                threatOutcomeForwardingService,
                blockingSignalBroadcaster
                );
    }

    @Bean(name = "contexaCentralAuditFacade")
    @ConditionalOnMissingBean
    public CentralAuditFacade centralAuditFacade(
            AuditLogRepository auditLogRepository,
            ApplicationEventPublisher eventPublisher,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
            ObjectProvider<EvidenceSigner> evidenceSigner) {
        CentralAuditFacade facade = new CentralAuditFacade(auditLogRepository, eventPublisher, objectMapper);
        // docs/agent A5-6: decision records are signed and linked.
        evidenceSigner.ifAvailable(facade::setEvidenceSigner);
        return facade;
    }

    /**
     * docs/agent A5-6: the signer of decision records and sealed evidence, HMAC-SHA256 over the configured keys
     * ({@code contexa.security.evidence.signing}); an ephemeral key, reported, without one.
     */
    @Bean(name = "contexaEvidenceSigner")
    @ConditionalOnMissingBean
    public EvidenceSigner evidenceSigner(EvidenceSigningProperties properties) {
        return HmacEvidenceSigner.of(properties.getKeys(), properties.getActiveKeyId());
    }

    @Bean(name = "contexaAuditPersistenceListener")
    @ConditionalOnMissingBean
    public AuditPersistenceListener auditPersistenceListener(CentralAuditFacade contexaCentralAuditFacade) {
        return new AuditPersistenceListener(contexaCentralAuditFacade);
    }

    @Bean(name = "contexaAuditingHandler")
    @ConditionalOnMissingBean
    public AuditingHandler auditingHandler(CentralAuditFacade contexaCentralAuditFacade) {
        return new AuditingHandler(contexaCentralAuditFacade);
    }

    @Bean(name = "contexaSoarContextProviderImpl")
    @ConditionalOnMissingBean
    public SoarContextProviderImpl soarContextProviderImpl(SecurityPlaneProperties securityPlaneProperties) {
        return new SoarContextProviderImpl(securityPlaneProperties);
    }

    @Bean(name = "contexaSecurityMonitoringService")
    @ConditionalOnMissingBean
    public SecurityMonitoringService securityMonitoringService(
            SecurityEventCollector eventCollector,
            SecurityPlaneProperties securityPlaneProperties) {
        return new SecurityMonitoringService(eventCollector, securityPlaneProperties);
    }

    @Bean(name = "contexaVectorStoreCacheLayer")
    @ConditionalOnMissingBean
    @ConditionalOnBean(name = "contexaVectorStore")
    public VectorStoreCacheLayer vectorStoreCacheLayer(
            @Qualifier("contexaVectorStore") VectorStore vectorStore,
            TieredStrategyProperties tieredStrategyProperties) {
        return new VectorStoreCacheLayer(vectorStore, tieredStrategyProperties);
    }

    @Bean(name = "contexaLayer1RagRetrievalExecutor", destroyMethod = "shutdown", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaLayer1RagRetrievalExecutor")
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

    @Bean(name = "contexaContextualStrategy")
    @ConditionalOnMissingBean
    @ConditionalOnBean({UnifiedLLMOrchestrator.class, UnifiedVectorService.class, BehaviorVectorService.class, BaselineLearningService.class})
    public Layer1ContextualStrategy contextualStrategy(
            UnifiedVectorService contexaUnifiedVectorService,
            SecurityContextDataStore dataStore,
            SecurityEventEnricher contexaSecurityEventEnricher,
            SecurityDecisionStandardPromptTemplate contexaSecurityDecisionStandardPromptTemplate,
            BehaviorVectorService contexaBehaviorVectorService,
            BaselineLearningService contexaBaselineLearningService,
            SecurityLearningService contexaSecurityLearningService,
            ObjectProvider<SaasBaselineSeedService> baselineSeedService,
            ObjectProvider<SaasThreatIntelligenceService> threatIntelligenceService,
            ObjectProvider<SaasThreatKnowledgePackService> threatKnowledgePackService,
            ObjectProvider<SaasDetectionStrategyPackService> detectionStrategyPackService,
            ObjectProvider<PromptContextAuditRecorder> promptContextAuditRecorder,
            PromptContextAuthorizationService contexaPromptContextAuthorizationService,
            ObjectProvider<PipelineOrchestrator> pipelineOrchestrator,
            StructuredOutputCapabilityRegistry contexaStructuredOutputCapabilityRegistry,
            @Qualifier("contexaLayer1RagRetrievalExecutor") ExecutorService contexaLayer1RagRetrievalExecutor,
            TieredStrategyProperties tieredStrategyProperties,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ObjectProvider<ModelSelectionStrategy> modelSelectionStrategy) {
        Layer1ContextualStrategy strategy = new Layer1ContextualStrategy(
                contexaUnifiedVectorService,
                dataStore,
                contexaSecurityEventEnricher,
                contexaSecurityDecisionStandardPromptTemplate,
                contexaBehaviorVectorService,
                contexaBaselineLearningService,
                contexaSecurityLearningService,
                baselineSeedService.getIfAvailable(),
                threatIntelligenceService.getIfAvailable(),
                threatKnowledgePackService.getIfAvailable(),
                detectionStrategyPackService.getIfAvailable(),
                contexaPromptContextAuthorizationService,
                promptContextAuditRecorder.getIfAvailable(),
                pipelineOrchestrator.getIfAvailable(),
                tieredStrategyProperties,
                contexaStructuredOutputCapabilityRegistry,
                contexaLayer1RagRetrievalExecutor);
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

    @Bean(name = "contexaExpertStrategy")
    @ConditionalOnMissingBean
    @ConditionalOnBean({UnifiedLLMOrchestrator.class, UnifiedVectorService.class, BehaviorVectorService.class, BaselineLearningService.class})
    public Layer2ExpertStrategy expertStrategy(
            @Autowired(required = false) ApprovalService approvalService,
            SecurityContextDataStore dataStore,
            SecurityEventEnricher contexaSecurityEventEnricher,
            SecurityDecisionStandardPromptTemplate contexaSecurityDecisionStandardPromptTemplate,
            UnifiedVectorService contexaUnifiedVectorService,
            BehaviorVectorService contexaBehaviorVectorService,
            BaselineLearningService contexaBaselineLearningService,
            TieredStrategyProperties tieredStrategyProperties,
            SecurityLearningService contexaSecurityLearningService,
            ObjectProvider<SaasBaselineSeedService> baselineSeedService,
            ObjectProvider<SaasThreatIntelligenceService> threatIntelligenceService,
            ObjectProvider<SaasThreatKnowledgePackService> threatKnowledgePackService,
            ObjectProvider<SaasDetectionStrategyPackService> detectionStrategyPackService,
            ObjectProvider<PromptContextAuditRecorder> promptContextAuditRecorder,
            PromptContextAuthorizationService contexaPromptContextAuthorizationService,
            ObjectProvider<PipelineOrchestrator> pipelineOrchestrator,
            StructuredOutputCapabilityRegistry contexaStructuredOutputCapabilityRegistry,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ObjectProvider<ModelSelectionStrategy> modelSelectionStrategy) {
        Layer2ExpertStrategy strategy = new Layer2ExpertStrategy(
                approvalService,
                dataStore,
                contexaSecurityEventEnricher,
                contexaSecurityDecisionStandardPromptTemplate,
                contexaUnifiedVectorService,
                contexaBehaviorVectorService,
                contexaBaselineLearningService,
                tieredStrategyProperties,
                contexaSecurityLearningService,
                baselineSeedService.getIfAvailable(),
                threatIntelligenceService.getIfAvailable(),
                threatKnowledgePackService.getIfAvailable(),
                detectionStrategyPackService.getIfAvailable(),
                contexaPromptContextAuthorizationService,
                promptContextAuditRecorder.getIfAvailable(),
                pipelineOrchestrator.getIfAvailable(),
                contexaStructuredOutputCapabilityRegistry);
        applyMinimumActionSettings(strategy, securityZeroTrustProperties);
        strategy.setModelSelectionStrategy(modelSelectionStrategy::getIfAvailable);
        return strategy;
    }

    @Bean(name = "contexaSecurityDecisionPostProcessor")
    @ConditionalOnBean(UnifiedVectorService.class)
    @ConditionalOnMissingBean
    public SecurityDecisionPostProcessor securityDecisionPostProcessor(
            SecurityContextDataStore dataStore,
            UnifiedVectorService contexaUnifiedVectorService,
            ObjectProvider<SecurityZeroTrustProperties> securityZeroTrustProperties) {
        SecurityDecisionPostProcessor postProcessor = new SecurityDecisionPostProcessor(dataStore, contexaUnifiedVectorService);
        SecurityZeroTrustProperties properties = securityZeroTrustProperties.getIfAvailable();
        if (properties != null && properties.getBaseline() != null && properties.getBaseline().getPromotion() != null) {
            // The past record of an allowed request the learning promotion holds is stored held (W5-1).
            postProcessor.setLearningPromotionSettings(properties.getBaseline().getPromotion().toPolicy());
        }
        return postProcessor;
    }

    @Bean(name = "contexaSecurityPlaneAgent")
    @ConditionalOnMissingBean
    public SecurityPlaneAgent securityPlaneAgent(
            SecurityMonitoringService securityMonitor,
            SecurityContextDataStore dataStore,
            CentralAuditFacade contexaCentralAuditFacade,
            SecurityEventProcessor processingOrchestrator,
            SecurityPlaneProperties securityPlaneProperties,
            @Qualifier("contexaLlmAnalysisExecutor") Executor llmAnalysisExecutor,
            ObjectProvider<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterProvider,
            ZeroTrustActionRepository zeroTrustActionRepository,
            ObjectProvider<SecurityDecisionEnforcementHandler> decisionEnforcementHandlerProvider,
            ObjectProvider<QueuedAgentEventRecheck> queuedAgentEventRecheckProvider
    ) {
        SecurityPlaneAgent agent = new SecurityPlaneAgent(
                securityMonitor, dataStore, contexaCentralAuditFacade,
                processingOrchestrator, securityPlaneProperties, llmAnalysisExecutor);
        // docs/agent RL-12 (QD): an agent's queued event is read against the stored decisions again at its turn.
        agent.setQueuedEventRecheck(event -> {
            QueuedAgentEventRecheck recheck = queuedAgentEventRecheckProvider.getIfAvailable();
            return recheck != null && recheck.answeredWithoutAnalysis(event);
        });
        agent.setAiSecurityDecisionObservationWriterSupplier(aiSecurityDecisionObservationWriterProvider::getIfAvailable);
        agent.setZeroTrustActionRepository(zeroTrustActionRepository);
        agent.setDecisionEnforcementHandlerSupplier(decisionEnforcementHandlerProvider::getIfAvailable);
        return agent;
    }

    /** docs/agent RL-12 (QD): what answers a queued agent event without a new analysis when its turn comes. */
    @Bean(name = "contexaQueuedAgentEventRecheck")
    @ConditionalOnMissingBean
    public QueuedAgentEventRecheck queuedAgentEventRecheck(
            ZeroTrustActionRepository zeroTrustActionRepository,
            ObjectProvider<AgentAllowReuse> agentAllowReuse,
            ObjectProvider<UnanalysedRequestRecorder> unanalysedRequestRecorder) {
        return new QueuedAgentEventRecheck(zeroTrustActionRepository, agentAllowReuse.getIfAvailable(),
                unanalysedRequestRecorder.getIfAvailable());
    }

    @Bean(name = "contexaEventTimeZoneRegistrar")
    @ConditionalOnMissingBean
    public EventTimeZoneRegistrar eventTimeZoneRegistrar(SecurityPlaneProperties securityPlaneProperties) {
        return new EventTimeZoneRegistrar(securityPlaneProperties);
    }

    @Bean(name = "contexaAuthorizationDenialRecorder")
    @ConditionalOnMissingBean
    public AuthorizationDenialRecorder authorizationDenialRecorder(
            ZeroTrustEventPublisher contexaZeroTrustEventPublisher,
            SecurityContextDataStore securityContextDataStore,
            ObjectProvider<RoleScopeCollector> roleScopeCollectorProvider,
            ContextObservationRecorder contexaContextObservationRecorder) {
        return new AuthorizationDenialRecorder(
                contexaZeroTrustEventPublisher, securityContextDataStore, roleScopeCollectorProvider.getIfAvailable(),
                contexaContextObservationRecorder);
    }

    /** Learns, once the user is verified, the request a restriction stopped, at a reduced weight (W5-2). */
    @Bean(name = "contexaVerificationLearningService")
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
    @Bean(name = "contexaLearningPromotionService")
    @ConditionalOnMissingBean
    public LearningPromotionService learningPromotionService(
            SecurityContextDataStore securityContextDataStore,
            ObjectProvider<SecurityLearningService> securityLearningService,
            ObjectProvider<ProtectableWorkProfileCollector> protectableWorkProfileCollector,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ObjectProvider<DistributedLockService> lockServiceProvider) {
        LearningPromotionService service = new LearningPromotionService(securityContextDataStore,
                securityLearningService.getIfAvailable(), protectableWorkProfileCollector.getIfAvailable(),
                securityZeroTrustProperties);
        // QF-28: a user's held requests are promoted under the configured lock service, one promotion at a time.
        service.setLockService(lockServiceProvider.getIfAvailable());
        return service;
    }

    /**
     * Keeps a request answered by the decision in force, which reaches no analysis, in its session (N-SES-1), and
     * learns the first one sent again after a passed step-up of those a web filter stopped (N-LRN-3).
     */
    @Bean(name = "contexaUnanalysedRequestRecorder")
    @ConditionalOnMissingBean
    public UnanalysedRequestRecorder unanalysedRequestRecorder(
            SessionNarrativeCollector contexaSessionNarrativeCollector,
            ContextObservationRecorder contexaContextObservationRecorder,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustEventPublisher contexaZeroTrustEventPublisher,
            ObjectProvider<VerificationLearningService> verificationLearningService) {
        UnanalysedRequestRecorder recorder = new UnanalysedRequestRecorder(contexaSessionNarrativeCollector,
                contexaContextObservationRecorder, securityZeroTrustProperties, contexaZeroTrustEventPublisher);
        recorder.setVerificationLearningService(verificationLearningService.getIfAvailable());
        return recorder;
    }

    @Bean(name = "contexaSessionRecordsIdChangeListener")
    @ConditionalOnMissingBean
    public SessionRecordsIdChangeListener sessionRecordsIdChangeListener(
            SecurityContextDataStore securityContextDataStore) {
        return new SessionRecordsIdChangeListener(securityContextDataStore);
    }

    @Bean(name = "contexaSynchronousProtectableDecisionService")
    @ConditionalOnMissingBean
    public SynchronousProtectableDecisionService synchronousProtectableDecisionService(
            ZeroTrustEventPublisher contexaZeroTrustEventPublisher,
            ZeroTrustEventListener contexaZeroTrustEventListener,
            SecurityPlaneAgent contexaSecurityPlaneAgent,
            ZeroTrustActionRepository actionRepository,
            ObjectProvider<UnanalysedRequestRecorder> unanalysedRequestRecorder,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ObjectProvider<AgentAllowReuse> agentAllowReuse,
            ObjectProvider<AgentDecisionFlights> agentDecisionFlights) {
        SynchronousProtectableDecisionService service = new SynchronousProtectableDecisionService(
                contexaZeroTrustEventPublisher,
                contexaZeroTrustEventListener,
                contexaSecurityPlaneAgent,
                actionRepository);
        service.setUnanalysedRequestRecorder(unanalysedRequestRecorder.getIfAvailable());
        // A1-5: contexa.security.zerotrust.protectable.unrecorded-agent-request
        service.setUnrecordedAgentRequest(securityZeroTrustProperties.getProtectable().getUnrecordedAgentRequest());
        // docs/agent F-1: past what an ALLOW answers, an agent's request is decided in place.
        service.setAgentAllowReuse(agentAllowReuse.getIfAvailable());
        // docs/agent RL-12: one agent's requests that come in numbers are analysed once per question.
        service.setAgentDecisionFlights(agentDecisionFlights.getIfAvailable());
        // PR-54: a synchronous request waits for its verdict as long as a request of the flights does.
        service.setDecisionWait(securityZeroTrustProperties.getAgent().getFlight().getWait());
        return service;
    }
    /**
     * The step-up flow of a CHALLENGE decided in the request starts through the identity module's starter (its
     * challenge filter), looked up when the answer is written so the bean order does not matter.
     */
    @Bean(name = "contexaZeroTrustExceptionHandler")
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

        /** BR-C11 (DD-52): each baseline is kept for the configured retention after its last learning. */
        @Bean(name = "contexaBaselineDataStore")
        @ConditionalOnMissingBean(BaselineDataStore.class)
        public RedisBaselineDataStore baselineDataStore(
                @Qualifier("contexaGeneralRedisTemplate") RedisTemplate<String, Object> redisTemplate,
                SecurityZeroTrustProperties securityZeroTrustProperties) {
            return new RedisBaselineDataStore(redisTemplate, securityZeroTrustProperties.getBaseline().getRetention());
        }

        @Bean(name = "contexaZeroTrustActionRedisRepository")
        @ConditionalOnMissingBean(ZeroTrustActionRepository.class)
        public ZeroTrustActionRedisRepository zeroTrustActionRedisRepository(
                @Qualifier("contexaGeneralRedisTemplate") RedisTemplate<String, Object> redisTemplate,
                StringRedisTemplate stringRedisTemplate) {
            return new ZeroTrustActionRedisRepository(redisTemplate, stringRedisTemplate);
        }

        @Bean(name = "contexaRedisProtectableRapidReentryRepository")
        @ConditionalOnMissingBean(ProtectableRapidReentryRepository.class)
        public RedisProtectableRapidReentryRepository redisProtectableRapidReentryRepository(
                StringRedisTemplate stringRedisTemplate) {
            return new RedisProtectableRapidReentryRepository(stringRedisTemplate);
        }

        @Bean(name = "contexaRedisThreatScoreUtil")
        @ConditionalOnMissingBean(ThreatScoreUtil.class)
        public RedisThreatScoreUtil redisThreatScoreUtil(
                @Qualifier("contexaGeneralRedisTemplate") RedisTemplate<String, Object> redisTemplate,
                SecurityZeroTrustProperties securityZeroTrustProperties) {
            return new RedisThreatScoreUtil(redisTemplate, securityZeroTrustProperties);
        }

        @Bean(name = "contexaRedisSecurityContextDataStore")
        @ConditionalOnMissingBean(SecurityContextDataStore.class)
        public RedisSecurityContextDataStore redisSecurityContextDataStore(
                @Qualifier("contexaGeneralRedisTemplate") RedisTemplate<String, Object> redisTemplate,
                ObjectProvider<SecurityPlaneProperties> securityPlaneProperties) {
            RedisSecurityContextDataStore store = new RedisSecurityContextDataStore(redisTemplate);
            SecurityPlaneProperties properties = securityPlaneProperties.getIfAvailable();
            if (properties != null) {
                store.setLoginFailureRetention(Duration.ofMinutes(
                        Math.max(1, properties.getContext().getLoginFailureWindowMinutes())));
                // BR-C14: how many observations each work profile and role scope keeps.
                store.setObservationCapacity(properties.getContext().getObservationCapacity());
            }
            return store;
        }

        @Bean(name = "contexaRedisDistributedLockService")
        @ConditionalOnMissingBean(DistributedLockService.class)
        public RedisDistributedLockService redisDistributedLockService(
                @Qualifier("contexaGeneralRedisTemplate") RedisTemplate<String, Object> redisTemplate) {
            return new RedisDistributedLockService(redisTemplate);
        }
    }

    @Bean(name = "contexaInMemoryZeroTrustActionRepository")
    @ConditionalOnMissingBean(ZeroTrustActionRepository.class)
      @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
      public InMemoryZeroTrustActionRepository inMemoryZeroTrustActionRepository(
              ObjectProvider<SecurityZeroTrustProperties> securityZeroTrustProperties) {
          // QF-42: the bound on users the store keeps; without a setting the one derived from the maximum heap.
          SecurityZeroTrustProperties properties = securityZeroTrustProperties.getIfAvailable();
          return new InMemoryZeroTrustActionRepository(properties != null && properties.getStandalone() != null
                  ? properties.getStandalone().getMaxDecisionUsers() : 0);
      }

      /** BR-C11 (DD-52): the in-memory store keeps each baseline for the same configured retention. */
      @Bean(name = "contexaBaselineDataStore")
      @ConditionalOnMissingBean(BaselineDataStore.class)
      @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
      public InMemoryBaselineDataStore baselineDataStore(SecurityZeroTrustProperties securityZeroTrustProperties) {
          Duration retention = securityZeroTrustProperties.getBaseline().getRetention();
          return new InMemoryBaselineDataStore(retention != null && !retention.isNegative() && !retention.isZero()
                  ? retention : RedisBaselineDataStore.DEFAULT_BASELINE_TTL);
      }

    @Bean(name = "contexaInMemoryProtectableRapidReentryRepository", destroyMethod = "close")
    @ConditionalOnMissingBean(ProtectableRapidReentryRepository.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
    public InMemoryProtectableRapidReentryRepository inMemoryProtectableRapidReentryRepository() {
        return new InMemoryProtectableRapidReentryRepository();
    }

    @Bean(name = "contexaInMemoryDistributedLockService")
    @ConditionalOnMissingBean(DistributedLockService.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
    public InMemoryDistributedLockService inMemoryDistributedLockService() {
        return new InMemoryDistributedLockService();
    }

    @Bean(name = "contexaInMemoryThreatScoreUtil")
    @ConditionalOnMissingBean(ThreatScoreUtil.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
    public InMemoryThreatScoreUtil inMemoryThreatScoreUtil(
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new InMemoryThreatScoreUtil(securityZeroTrustProperties);
    }

    @Bean(name = "contexaInMemorySecurityContextDataStore")
    @ConditionalOnMissingBean(SecurityContextDataStore.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
    public InMemorySecurityContextDataStore inMemorySecurityContextDataStore(
            ObjectProvider<SecurityPlaneProperties> securityPlaneProperties,
            ObjectProvider<SecurityZeroTrustProperties> securityZeroTrustProperties) {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        SecurityPlaneProperties properties = securityPlaneProperties.getIfAvailable();
        if (properties != null) {
            store.setLoginFailureRetention(Duration.ofMinutes(
                    Math.max(1, properties.getContext().getLoginFailureWindowMinutes())));
            // BR-C14: how many observations each work profile and role scope keeps.
            store.setObservationCapacity(properties.getContext().getObservationCapacity());
        }
        // QF-42: the byte budget of the held learning records; without a setting the one derived from the maximum heap.
        SecurityZeroTrustProperties zeroTrustProperties = securityZeroTrustProperties.getIfAvailable();
        if (zeroTrustProperties != null && zeroTrustProperties.getStandalone() != null) {
            store.setHeldLearningBudgetBytes(zeroTrustProperties.getStandalone().getMaxHeldLearningBytes());
        }
        return store;
    }

    /**
     * QF-32: the default infrastructure mode keeps what is learned in memory; one warning at startup says so when the
     * in-memory baseline, observation and hold stores are the ones in use.
     */
    @Bean(name = "contexaStandaloneLearningStateWarning")
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
    public StandaloneLearningStateWarning standaloneLearningStateWarning(
            ObjectProvider<BaselineDataStore> baselineDataStore,
            ObjectProvider<SecurityContextDataStore> securityContextDataStore) {
        return new StandaloneLearningStateWarning(baselineDataStore::getIfAvailable,
                securityContextDataStore::getIfAvailable);
    }

    /** Discards the late writes of a deleted account's requests for the analysis budget and a margin (Q-15). */
    @Bean(name = "contexaDeletedAccountWriteFence")
    @ConditionalOnMissingBean
    public DeletedAccountWriteFence deletedAccountWriteFence(
            ObjectProvider<SecurityContextDataStore> securityContextDataStore,
            ObjectProvider<SecurityPlaneProperties> securityPlaneProperties) {
        SecurityPlaneProperties.AgentSettings agent =
                securityPlaneProperties.getIfAvailable(SecurityPlaneProperties::new).getAgent();
        Duration retention = DeletedAccountWriteFence.retention(
                agent.getEventTimeoutMs(), agent.getMaxDeferredRetries(), agent.getDeletedAccountFenceMarginMs());
        return new DeletedAccountWriteFence(securityContextDataStore.getIfAvailable(), retention);
    }

    @Bean(name = "contexaUserEngineStatePurger")
    @ConditionalOnMissingBean
    public UserEngineStatePurger userEngineStatePurger(
            ZeroTrustActionRepository zeroTrustActionRepository,
            ObjectProvider<BlockingSignalBroadcaster> blockingSignalBroadcaster,
            ObjectProvider<BlockMfaStateStore> blockMfaStateStore,
            ObjectProvider<BaselineDataStore> baselineDataStore,
            ObjectProvider<SecurityContextDataStore> securityContextDataStore,
            ObjectProvider<ColdPathEventProcessor> coldPathEventProcessor,
            @Qualifier("contexaVectorStore") ObjectProvider<VectorStore> vectorStore,
            ObjectProvider<IForceLogoutService> forceLogoutService,
            ObjectProvider<UserStatePurgeContributor> contributors,
            ObjectProvider<VectorStoreCacheLayer> vectorStoreCacheLayer,
            ObjectProvider<DeletedAccountWriteFence> deletedAccountWriteFence) {
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
        purger.setDeletedAccountWriteFence(deletedAccountWriteFence.getIfAvailable());
        return purger;
    }

    /** Removes the security bridge's mirror users of a deleted account; skips itself without the user tables. */
    @Bean(name = "contexaBridgeMirrorUserStatePurgeContributor")
    public UserStatePurgeContributor bridgeMirrorUserStatePurgeContributor(
            ObjectProvider<UserRepository> userRepository,
            ObjectProvider<BridgeUserProfileRepository> bridgeUserProfileRepository,
            ObjectProvider<UserRolePermissionRepository> userRolePermissionRepository,
            @Qualifier("contexaTransactionManager") ObjectProvider<PlatformTransactionManager> contexaTransactionManager) {
        return new BridgeMirrorUserStatePurgeContributor(userRepository, bridgeUserProfileRepository,
                userRolePermissionRepository, contexaTransactionManager);
    }

    @Bean(name = "contexaUserAccountDeletionListener")
    @ConditionalOnMissingBean
    public UserAccountDeletionListener userAccountDeletionListener(UserEngineStatePurger contexaUserEngineStatePurger) {
        return new UserAccountDeletionListener(contexaUserEngineStatePurger);
    }

    @Bean(name = "contexaInMemoryStateSweeper", destroyMethod = "close")
    @ConditionalOnMissingBean
    public InMemoryStateSweeper inMemoryStateSweeper(ObjectProvider<ExpiringStateStore> expiringStateStores) {
        return new InMemoryStateSweeper(
                () -> expiringStateStores.orderedStream().toList(), InMemoryStateSweeper.DEFAULT_INTERVAL);
    }
}





