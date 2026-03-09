package io.contexa.autoconfigure.core.autonomous;

import io.contexa.autoconfigure.core.hcad.CoreHCADAutoConfiguration;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.SecurityEventProcessor;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger;
import io.contexa.contexacore.autonomous.event.SecurityEventCollector;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.exception.ZeroTrustExceptionHandler;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.handler.handler.AuditingHandler;
import io.contexa.contexacore.autonomous.repository.*;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
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
        TieredStrategyProperties.class
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
    public SecurityPromptTemplate securityPromptTemplate(
            SecurityEventEnricher securityEventEnricher,
            TieredStrategyProperties tieredStrategyProperties) {
        return new SecurityPromptTemplate(securityEventEnricher, tieredStrategyProperties);
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
            @Autowired(required = false) DistributedLockService lockService) {
        return new AdminOverrideService(securityLearningService, actionRedisRepository, lockService);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuditingHandler auditingHandler() {
        return new AuditingHandler();
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
    public Layer1ContextualStrategy contextualStrategy(
            UnifiedLLMOrchestrator llmOrchestrator,
            UnifiedVectorService unifiedVectorService,
            SecurityContextDataStore dataStore,
            SecurityEventEnricher securityEventEnricher,
            SecurityPromptTemplate securityPromptTemplate,
            BehaviorVectorService behaviorVectorService,
            BaselineLearningService baselineLearningService,
            SecurityLearningService securityLearningService,
            TieredStrategyProperties tieredStrategyProperties) {
        return new Layer1ContextualStrategy(
                llmOrchestrator, unifiedVectorService, dataStore, securityEventEnricher, securityPromptTemplate, behaviorVectorService,
                baselineLearningService, securityLearningService, tieredStrategyProperties);
    }

    @Bean
    @ConditionalOnMissingBean
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
            SecurityLearningService securityLearningService) {
        return new Layer2ExpertStrategy(
                llmOrchestrator, approvalService, dataStore,
                securityEventEnricher, securityPromptTemplate, unifiedVectorService,
                behaviorVectorService, baselineLearningService,
                tieredStrategyProperties, securityLearningService);
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
            SecurityPlaneAuditLogger auditLogger,
            SecurityEventProcessor processingOrchestrator,
            SecurityPlaneProperties securityPlaneProperties,
            @Qualifier("llmAnalysisExecutor") Executor llmAnalysisExecutor
            ) {
        return new SecurityPlaneAgent(
                securityMonitor, dataStore, auditLogger,
                processingOrchestrator, securityPlaneProperties,llmAnalysisExecutor);
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





