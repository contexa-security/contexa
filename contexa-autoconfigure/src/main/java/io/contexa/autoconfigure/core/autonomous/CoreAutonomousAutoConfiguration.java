package io.contexa.autoconfigure.core.autonomous;

import io.contexa.autoconfigure.core.hcad.CoreHCADAutoConfiguration;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.SecurityEventProcessor;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.autonomous.handler.handler.AuditingHandler;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.autonomous.service.impl.SoarContextProviderImpl;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.properties.*;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.List;

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
        SecurityPipelineProperties.class
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
    public TieredStrategyProperties tieredStrategyProperties() {
        return new TieredStrategyProperties();
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustActionRedisRepository zeroTrustActionRedisRepository(
            RedisTemplate<String, Object> redisTemplate,
            StringRedisTemplate stringRedisTemplate) {
        return new ZeroTrustActionRedisRepository(redisTemplate, stringRedisTemplate);
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
            BaselineLearningService baselineLearningService,
            SecurityDecisionPostProcessor securityDecisionPostProcessor) {
        return new SecurityLearningService(baselineLearningService, securityDecisionPostProcessor);
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminOverrideService adminOverrideService(
            SecurityLearningService securityLearningService,
            ZeroTrustActionRedisRepository actionRedisRepository,
            @Autowired(required = false) RedisDistributedLockService lockService) {
        return new AdminOverrideService(securityLearningService, actionRedisRepository, lockService);
    }

    @Bean
    @ConditionalOnMissingBean
    public VectorStoreCacheLayer vectorStoreCacheLayer(VectorStore vectorStore,
            TieredStrategyProperties tieredStrategyProperties) {
        return new VectorStoreCacheLayer(vectorStore, tieredStrategyProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuditingHandler auditingHandler() {
        return new AuditingHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    public ThreatScoreUtil threatScoreOrchestrator(RedisTemplate<String, Object> redisTemplate,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new ThreatScoreUtil(redisTemplate, securityZeroTrustProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public SoarContextProviderImpl soarContextProviderImpl(SecurityPlaneProperties securityPlaneProperties) {
        return new SoarContextProviderImpl(securityPlaneProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityMonitoringService securityMonitoringService(
            KafkaSecurityEventCollector kafkaCollector) {
        return new SecurityMonitoringService(kafkaCollector);
    }

    @Bean
    @ConditionalOnMissingBean
    public Layer1ContextualStrategy contextualStrategy(
            UnifiedLLMOrchestrator llmOrchestrator,
            UnifiedVectorService unifiedVectorService,
            RedisTemplate<String, Object> redisTemplate,
            SecurityEventEnricher securityEventEnricher,
            SecurityPromptTemplate securityPromptTemplate,
            BehaviorVectorService behaviorVectorService,
            BaselineLearningService baselineLearningService,
            SecurityLearningService securityLearningService,
            TieredStrategyProperties tieredStrategyProperties) {
        return new Layer1ContextualStrategy(
                llmOrchestrator, unifiedVectorService, redisTemplate, securityEventEnricher,
                securityPromptTemplate, behaviorVectorService, baselineLearningService,
                securityLearningService, tieredStrategyProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public Layer2ExpertStrategy expertStrategy(
            UnifiedLLMOrchestrator llmOrchestrator,
            @Autowired(required = false) ApprovalService approvalService,
            RedisTemplate<String, Object> redisTemplate,
            SecurityEventEnricher securityEventEnricher,
            SecurityPromptTemplate securityPromptTemplate,
            UnifiedVectorService unifiedVectorService,
            BehaviorVectorService behaviorVectorService,
            BaselineLearningService baselineLearningService,
            TieredStrategyProperties tieredStrategyProperties,
            SecurityLearningService securityLearningService) {
        return new Layer2ExpertStrategy(
                llmOrchestrator, approvalService, redisTemplate, securityEventEnricher,
                securityPromptTemplate, unifiedVectorService, behaviorVectorService,
                baselineLearningService, tieredStrategyProperties, securityLearningService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityEventProcessor securityEventProcessingOrchestrator(
            List<SecurityEventHandler> handlers) {
        return new SecurityEventProcessor(handlers);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityPlaneAgent securityPlaneAgent(
            SecurityMonitoringService securityMonitor,
            RedisTemplate<String, Object> redisTemplate,
            SecurityPlaneAuditLogger auditLogger,
            SecurityEventProcessor processingOrchestrator,
            SecurityPlaneProperties securityPlaneProperties) {
        return new SecurityPlaneAgent(
                securityMonitor, redisTemplate, auditLogger, processingOrchestrator, securityPlaneProperties);
    }
}
