package io.contexa.autoconfigure.core.autonomous;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger;
import io.contexa.contexacore.autonomous.domain.RiskAssessment;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;

import io.contexa.contexacore.properties.SecurityKafkaProperties;

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;

import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.handler.handler.ProcessingExecutionHandler;
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.handler.strategy.ColdPathStrategy;
import io.contexa.contexacore.autonomous.handler.strategy.ProcessingStrategy;
import io.contexa.contexacore.autonomous.security.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;


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
    public KafkaSecurityEventCollector kafkaSecurityEventCollector(
            ObjectMapper objectMapper,
            KafkaTemplate<String, String> kafkaTemplate,
            SecurityKafkaProperties securityKafkaProperties) {
        return new KafkaSecurityEventCollector(objectMapper, kafkaTemplate, securityKafkaProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustEventListener zeroTrustEventListener(
            KafkaSecurityEventPublisher kafkaSecurityEventPublisher,
            RedisTemplate<String, Object> redisTemplate,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new ZeroTrustEventListener(kafkaSecurityEventPublisher, redisTemplate, securityZeroTrustProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public KafkaSecurityEventPublisher kafkaSecurityEventPublisher(
            KafkaTemplate<String, Object> kafkaTemplate,
            SecurityKafkaProperties securityKafkaProperties) {
        return new KafkaSecurityEventPublisher(kafkaTemplate, securityKafkaProperties);
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
    public ProcessingExecutionHandler processingExecutionHandler(
            List<ProcessingStrategy> processingStrategies) {
        return new ProcessingExecutionHandler(processingStrategies);
    }

    @Bean
    @ConditionalOnMissingBean
    public ColdPathStrategy coldPathStrategy(ColdPathEventProcessor coldPathEventProcessor) {
        return new ColdPathStrategy(coldPathEventProcessor);
    }

    @Bean
    @ConditionalOnMissingBean
    public LlmAnalysisEventListener llmAnalysisEventListener() {
        return new LlmAnalysisEventListener() {
            @Override public void onContextCollected(String userId, String requestPath, String analysisRequirement) {}
            @Override public void onLayer1Start(String userId, String requestPath) {}
            @Override public void onLayer1Complete(String userId, String action, Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs) {}
            @Override public void onLayer2Start(String userId, String requestPath, String reason) {}
            @Override public void onLayer2Complete(String userId, String action, Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs) {}
            @Override public void onDecisionApplied(String userId, String action, String layer, String requestPath) {}
            @Override public void onError(String userId, String message) {}
        };
    }

    @Bean
    @ConditionalOnMissingBean
    public ColdPathEventProcessor coldPathEventProcessor(
            Layer1ContextualStrategy contextualStrategy,
            Layer2ExpertStrategy expertStrategy,
            LlmAnalysisEventListener llmAnalysisEventListener) {
        return new ColdPathEventProcessor(contextualStrategy, expertStrategy, llmAnalysisEventListener);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityDecisionEnforcementHandler securityDecisionEnforcementHandler(
            ZeroTrustActionRedisRepository actionRedisRepository,
            AdminOverrideService adminOverrideService,
            SecurityLearningService securityLearningService) {
        return new SecurityDecisionEnforcementHandler(
                actionRedisRepository, adminOverrideService, securityLearningService);
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
