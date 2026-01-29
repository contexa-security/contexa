package io.contexa.autoconfigure.core.autonomous;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.ISecurityPlaneAgent;
import io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger;
import io.contexa.contexacore.autonomous.domain.RiskAssessment;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.event.backpressure.BackpressureManager;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.monitoring.DeadLetterQueueMonitor;
import io.contexa.contexacore.autonomous.event.monitoring.RedisMemoryMonitor;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.orchestrator.SecurityPlaneEventListener;
import io.contexa.contexacore.autonomous.orchestrator.handler.ProcessingExecutionHandler;
import io.contexa.contexacore.autonomous.orchestrator.strategy.ColdPathStrategy;
import io.contexa.contexacore.autonomous.orchestrator.strategy.ProcessingStrategy;
import io.contexa.contexacore.autonomous.security.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;

import java.util.List;

@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa.autonomous", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({ ContexaProperties.class, SecurityPlaneProperties.class })
public class CoreAutonomousEventAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public KafkaSecurityEventCollector kafkaSecurityEventCollector(ObjectMapper objectMapper) {
        return new KafkaSecurityEventCollector(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustEventListener zeroTrustEventListener(
            KafkaSecurityEventPublisher kafkaSecurityEventPublisher,
            RedisTemplate<String, Object> redisTemplate,
            SecurityDecisionPostProcessor securityDecisionPostProcessor) {
        return new ZeroTrustEventListener(kafkaSecurityEventPublisher, redisTemplate, securityDecisionPostProcessor);
    }

    @Bean
    @ConditionalOnMissingBean
    public KafkaSecurityEventPublisher kafkaSecurityEventPublisher(
            KafkaTemplate<String, Object> kafkaTemplate) {
        return new KafkaSecurityEventPublisher(kafkaTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustEventPublisher zeroTrustEventPublisher(
            ApplicationEventPublisher applicationEventPublisher,
            TieredStrategyProperties tieredStrategyProperties) {
        return new ZeroTrustEventPublisher(applicationEventPublisher, tieredStrategyProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public DeadLetterQueueMonitor deadLetterQueueMonitor(
            KafkaTemplate<String, Object> kafkaTemplate,
            MeterRegistry meterRegistry) {
        return new DeadLetterQueueMonitor(kafkaTemplate, meterRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    public RedisMemoryMonitor redisMemoryMonitor(
            RedisTemplate<String, Object> redisTemplate,
            MeterRegistry meterRegistry) {
        return new RedisMemoryMonitor(redisTemplate, meterRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    public BackpressureManager backpressureManager(
            MeterRegistry meterRegistry,
            CircuitBreakerRegistry circuitBreakerRegistry) {
        return new BackpressureManager(meterRegistry, circuitBreakerRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    public ProcessingExecutionHandler processingExecutionHandler(
            List<ProcessingStrategy> processingStrategies,
            ApplicationEventPublisher applicationEventPublisher) {
        return new ProcessingExecutionHandler(processingStrategies, applicationEventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityPlaneEventListener securityPlaneEventListener(ISecurityPlaneAgent securityPlaneAgent) {
        return new SecurityPlaneEventListener(securityPlaneAgent);
    }

    @Bean
    @ConditionalOnMissingBean
    public ColdPathStrategy coldPathStrategy(ColdPathEventProcessor coldPathEventProcessor) {
        return new ColdPathStrategy(coldPathEventProcessor);
    }

    @Bean
    @ConditionalOnMissingBean
    public ColdPathEventProcessor coldPathEventProcessor(
            RedisTemplate<String, Object> redisTemplate,
            Layer1ContextualStrategy contextualStrategy,
            Layer2ExpertStrategy expertStrategy) {
        return new ColdPathEventProcessor(redisTemplate, contextualStrategy, expertStrategy);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityDecisionPostProcessor securityDecisionPostProcessor(
            RedisTemplate<String, Object> redisTemplate,
            UnifiedVectorService unifiedVectorService) {
        return new SecurityDecisionPostProcessor(redisTemplate, unifiedVectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityPlaneAuditLogger securityPlaneAuditLogger(
            AuditLogRepository auditLogRepository,
            ObjectMapper objectMapper) {
        return new SecurityPlaneAuditLogger(auditLogRepository, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskAssessment riskAssessment() {
        return new RiskAssessment();
    }
}
