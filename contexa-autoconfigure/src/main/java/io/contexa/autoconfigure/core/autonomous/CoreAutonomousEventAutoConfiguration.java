package io.contexa.autoconfigure.core.autonomous;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.ISecurityPlaneAgent;
import io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger;
import io.contexa.contexacore.autonomous.authorization.RiskAssessment;
import io.contexa.contexacore.autonomous.event.backpressure.BackpressureManager;
import io.contexa.contexacore.autonomous.event.decision.UnifiedEventPublishingDecisionEngine;
import io.contexa.contexacore.autonomous.event.filter.SecurityEventPublishingFilter;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.autonomous.event.listener.RedisSecurityEventCollector;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.monitoring.DeadLetterQueueMonitor;
import io.contexa.contexacore.autonomous.event.monitoring.RedisMemoryMonitor;
import io.contexa.contexacore.autonomous.event.publisher.AuthorizationEventPublisher;
import io.contexa.contexacore.autonomous.event.publisher.CompositeSecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.publisher.RedisSecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.sampling.AdaptiveSamplingEngine;
import io.contexa.contexacore.autonomous.orchestrator.handler.ProcessingExecutionHandler;
import io.contexa.contexacore.autonomous.orchestrator.SecurityPlaneEventListener;
import io.contexa.contexacore.autonomous.orchestrator.strategy.ColdPathStrategy;
import io.contexa.contexacore.autonomous.orchestrator.strategy.ProcessingStrategy;
import io.contexa.contexacore.autonomous.orchestrator.strategy.RealtimeBlockStrategy;
import io.contexa.contexacore.autonomous.orchestrator.strategy.SoarOrchestrationStrategy;
import io.contexa.contexacore.autonomous.processor.EventDeduplicator;
import io.contexa.contexacore.autonomous.processor.EventNormalizer;
import io.contexa.contexacore.autonomous.security.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.std.components.event.AuditLogger;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.micrometer.core.instrument.MeterRegistry;
import org.redisson.api.RedissonClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.kafka.core.KafkaTemplate;

import java.util.List;

/**
 * Core Autonomous Event AutoConfiguration
 *
 * Contexa Core의 Autonomous Event 관련 컴포넌트 자동 구성
 *
 * 포함된 컴포넌트 (약 27개):
 * - Event Listeners (4개)
 * - Event Publishers (5개)
 * - Event Monitoring (2개)
 * - Event Processing (5개)
 * - Orchestrator Handlers (3개)
 * - Orchestrator Strategies (4개)
 * - Security Processors (2개)
 * - Audit & Authorization (2개)
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.autonomous",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties(ContexaProperties.class)
public class CoreAutonomousEventAutoConfiguration {

    // ========== Event Listeners ==========

    @Bean
    @ConditionalOnMissingBean
    public KafkaSecurityEventCollector kafkaSecurityEventCollector(ObjectMapper objectMapper) {
        return new KafkaSecurityEventCollector(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public RedisSecurityEventCollector redisSecurityEventCollector(
            RedissonClient redissonClient,
            StringRedisTemplate stringRedisTemplate,
            ObjectMapper objectMapper,
            RedisMessageListenerContainer messageListenerContainer) {
        return new RedisSecurityEventCollector(redissonClient, stringRedisTemplate, objectMapper, messageListenerContainer);
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustEventListener zeroTrustEventListener(
            KafkaSecurityEventPublisher kafkaSecurityEventPublisher,
            SecurityEventEnricher securityEventEnricher,
            RedisTemplate<String, Object> redisTemplate) {
        return new ZeroTrustEventListener(kafkaSecurityEventPublisher, securityEventEnricher, redisTemplate);
    }

    // ========== Event Publishers ==========

    /**
     * AuthorizationEventPublisher - 인가 이벤트 발행자
     *
     * D1: TieredStrategyProperties 주입 추가
     * - Security 설정에서 trustedProxies 목록 사용
     * - X-Forwarded-For 스푸핑 방지
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthorizationEventPublisher authorizationEventPublisher(
            ApplicationEventPublisher applicationEventPublisher,
            TieredStrategyProperties tieredStrategyProperties) {
        return new AuthorizationEventPublisher(applicationEventPublisher, tieredStrategyProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public CompositeSecurityEventPublisher compositeSecurityEventPublisher(
            KafkaSecurityEventPublisher kafkaSecurityEventPublisher,
            RedisSecurityEventPublisher redisSecurityEventPublisher) {
        return new CompositeSecurityEventPublisher(kafkaSecurityEventPublisher, redisSecurityEventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    public KafkaSecurityEventPublisher kafkaSecurityEventPublisher(
            KafkaTemplate<String, Object> kafkaTemplate,
            ObjectMapper objectMapper) {
        return new KafkaSecurityEventPublisher(kafkaTemplate, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public RedisSecurityEventPublisher redisSecurityEventPublisher(
            RedisTemplate<String, Object> redisTemplate,
            ObjectMapper objectMapper) {
        return new RedisSecurityEventPublisher(redisTemplate, objectMapper);
    }

    // ========== Event Monitoring ==========

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

    // ========== Event Processing ==========

    @Bean
    @ConditionalOnMissingBean
    public BackpressureManager backpressureManager(
            MeterRegistry meterRegistry,
            CircuitBreakerRegistry circuitBreakerRegistry) {
        return new BackpressureManager(meterRegistry, circuitBreakerRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    public UnifiedEventPublishingDecisionEngine unifiedEventPublishingDecisionEngine(
            RedisTemplate<String, Object> redisTemplate,
            AdaptiveSamplingEngine adaptiveSamplingEngine) {
        return new UnifiedEventPublishingDecisionEngine(redisTemplate, adaptiveSamplingEngine);
    }

    @Bean
    @ConditionalOnMissingBean
    public AdaptiveSamplingEngine adaptiveSamplingEngine(RedisTemplate<String, Object> redisTemplate) {
        return new AdaptiveSamplingEngine(redisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public EventDeduplicator eventDeduplicator() {
        return new EventDeduplicator();
    }

    @Bean
    @ConditionalOnMissingBean
    public EventNormalizer eventNormalizer() {
        return new EventNormalizer();
    }

//    @Bean
//    @ConditionalOnMissingBean
    public SecurityEventPublishingFilter securityEventPublishingFilter(
            ApplicationEventPublisher applicationEventPublisher,
            UnifiedEventPublishingDecisionEngine unifiedEventPublishingDecisionEngine) {
        return new SecurityEventPublishingFilter(applicationEventPublisher, unifiedEventPublishingDecisionEngine);
    }

    // ========== Orchestrator Handlers ==========

    @Bean
    @ConditionalOnMissingBean
    public ProcessingExecutionHandler processingExecutionHandler(
            List<ProcessingStrategy> processingStrategies,
            ApplicationEventPublisher applicationEventPublisher) {
        return new ProcessingExecutionHandler(processingStrategies, applicationEventPublisher);
    }

    // AI Native: SessionInvalidationHandler 제거 (ZeroTrustSecurityService의 BLOCK action으로 대체)

    @Bean
    @ConditionalOnMissingBean
    public SecurityPlaneEventListener securityPlaneEventListener(ISecurityPlaneAgent securityPlaneAgent) {
        return new SecurityPlaneEventListener(securityPlaneAgent);
    }

    // ========== Orchestrator Strategies ==========

    @Bean
    @ConditionalOnMissingBean
    public ColdPathStrategy coldPathStrategy(ColdPathEventProcessor coldPathEventProcessor) {
        return new ColdPathStrategy(coldPathEventProcessor);
    }

    // AI Native: HotPathStrategy 제거 (삭제된 Hot Path 전략)

    @Bean
    @ConditionalOnMissingBean
    public RealtimeBlockStrategy realtimeBlockStrategy(RedisTemplate<String, Object> redisTemplate) {
        return new RealtimeBlockStrategy(redisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public SoarOrchestrationStrategy soarOrchestrationStrategy() {
        return new SoarOrchestrationStrategy();
    }

    // ========== Security Processors ==========

    /**
     * ColdPathEventProcessor - Cold Path 이벤트 처리기 (AI Native)
     *
     * AI Native 전환:
     * - ZeroTrustDecisionEngine 제거
     * - HotPathEventProcessor 제거 (모든 요청은 Cold Path)
     */
    @Bean
    @ConditionalOnMissingBean
    public ColdPathEventProcessor coldPathEventProcessor(
            RedisTemplate<String, Object> redisTemplate,
            Layer1ContextualStrategy contextualStrategy,
            Layer2ExpertStrategy expertStrategy) {
        return new ColdPathEventProcessor(redisTemplate, contextualStrategy, expertStrategy);
    }

    // ========== Audit & Authorization ==========

    @Bean
    @ConditionalOnMissingBean
    public SecurityPlaneAuditLogger securityPlaneAuditLogger(
            AuditLogger auditLogger,
            @Autowired(required = false) AuditLogRepository auditLogRepository,
            ObjectMapper objectMapper) {
        return new SecurityPlaneAuditLogger(auditLogger, auditLogRepository, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskAssessment riskAssessment() {
        return new RiskAssessment();
    }
}
