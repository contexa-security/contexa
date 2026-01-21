package io.contexa.autoconfigure.core.autonomous;

import io.contexa.autoconfigure.core.hcad.CoreHCADAutoConfiguration;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger;
import io.contexa.contexacore.autonomous.config.SecurityPlaneConfiguration;
import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventProcessingOrchestrator;
import io.contexa.contexacore.autonomous.orchestrator.ThreatScoreOrchestrator;
import io.contexa.contexacore.autonomous.orchestrator.handler.AuditingHandler;
import io.contexa.contexacore.autonomous.orchestrator.handler.MetricsHandler;
import io.contexa.contexacore.autonomous.orchestrator.handler.RoutingDecisionHandler;
import io.contexa.contexacore.autonomous.processor.EventDeduplicator;
import io.contexa.contexacore.autonomous.processor.EventNormalizer;
import io.contexa.contexacore.autonomous.service.AdminOverrideRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.service.impl.SoarContextProviderImpl;
import io.contexa.contexacore.autonomous.strategy.DynamicStrategySelector;
import io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.autonomous.tiered.detection.MaliciousPatternDetector;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.properties.*;
import io.contexa.contexacore.repository.SecurityIncidentRepository;
import io.contexa.contexacore.repository.ThreatIndicatorRepository;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.core.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.rag.processors.ThreatCorrelator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.List;


@AutoConfiguration
@AutoConfigureAfter(CoreHCADAutoConfiguration.class)
@ConditionalOnProperty(
    prefix = "contexa.autonomous",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
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
@Import({
    SecurityPlaneConfiguration.class
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
    public DynamicStrategySelector dynamicStrategySelector(
            ThreatCorrelator threatCorrelator) {
        return new DynamicStrategySelector(threatCorrelator);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public MaliciousPatternDetector maliciousPatternDetector(
            @Qualifier("stringRedisTemplate") RedisTemplate<String, String> stringRedisTemplate) {
        return new MaliciousPatternDetector(stringRedisTemplate);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public TieredStrategyProperties tieredStrategyProperties() {
        return new TieredStrategyProperties();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public AdminOverrideRepository adminOverrideRepository(
            RedisTemplate<String, Object> redisTemplate) {
        return new AdminOverrideRepository(redisTemplate);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public SecurityPromptTemplate securityPromptTemplate(
            SecurityEventEnricher securityEventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            BaselineLearningService baselineLearningService) {
        return new SecurityPromptTemplate(securityEventEnricher, tieredStrategyProperties,baselineLearningService);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public AdminOverrideService adminOverrideService(
            AdminOverrideRepository adminOverrideRepository,
            BaselineLearningService baselineLearningService,
            RedisTemplate<String, Object> redisTemplate) {
        return new AdminOverrideService(adminOverrideRepository, baselineLearningService, redisTemplate);
    }

    

    
    @Bean
    @ConditionalOnMissingBean
    public VectorStoreCacheLayer vectorStoreCacheLayer() {
        return new VectorStoreCacheLayer();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuditingHandler auditingHandler() {
        return new AuditingHandler();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public MetricsHandler metricsHandler(
            RedisTemplate<String, Object> redisTemplate) {
        return new MetricsHandler(redisTemplate);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public ThreatScoreOrchestrator threatScoreOrchestrator(RedisTemplate<String, Object> redisTemplate) {
        return new ThreatScoreOrchestrator(redisTemplate);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public SoarContextProviderImpl soarContextProviderImpl() {
        return new SoarContextProviderImpl();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public SecurityMonitoringService securityMonitoringService(
            KafkaSecurityEventCollector kafkaCollector,
            SecurityIncidentRepository securityIncidentRepository,
            List<ThreatEvaluationStrategy> evaluationStrategies,
            EventNormalizer eventNormalizer,
            EventDeduplicator eventDeduplicator) {
        return new SecurityMonitoringService(
            kafkaCollector, securityIncidentRepository,
            evaluationStrategies, eventNormalizer, eventDeduplicator
        );
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
            SecurityDecisionPostProcessor securityDecisionPostProcessor,
            TieredStrategyProperties tieredStrategyProperties) {
        return new Layer1ContextualStrategy(
            llmOrchestrator, unifiedVectorService, redisTemplate, securityEventEnricher,
            securityPromptTemplate, behaviorVectorService, baselineLearningService,
            securityDecisionPostProcessor, tieredStrategyProperties
        );
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
            TieredStrategyProperties tieredStrategyProperties) {
        return new Layer2ExpertStrategy(
            llmOrchestrator, approvalService, redisTemplate, securityEventEnricher,
            securityPromptTemplate, unifiedVectorService, behaviorVectorService,
            baselineLearningService, tieredStrategyProperties
        );
    }
    
    @Bean
    @ConditionalOnMissingBean
    public RoutingDecisionHandler routingDecisionHandler() {
        return new RoutingDecisionHandler();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public SecurityEventProcessingOrchestrator securityEventProcessingOrchestrator(
            List<SecurityEventHandler> handlers) {
        return new SecurityEventProcessingOrchestrator(handlers);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public SecurityPlaneAgent securityPlaneAgent(
            SecurityMonitoringService securityMonitor,
            SecurityIncidentRepository incidentRepository,
            RedisTemplate<String, Object> redisTemplate,
            ApplicationEventPublisher eventPublisher,
            SecurityPlaneAuditLogger auditLogger,
            SecurityEventProcessingOrchestrator processingOrchestrator) {
        return new SecurityPlaneAgent(
            securityMonitor, redisTemplate, eventPublisher, auditLogger, processingOrchestrator
        );
    }
}