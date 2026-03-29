package io.contexa.autoconfigure.core.autonomous;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.blocking.BlockingDecisionRegistry;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.domain.RiskAssessment;
import io.contexa.contexacore.autonomous.event.*;
import io.contexa.contexacore.autonomous.event.listener.InMemorySecurityEventCollector;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.InMemorySecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.handler.handler.ProcessingExecutionHandler;
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.handler.strategy.ColdPathStrategy;
import io.contexa.contexacore.autonomous.handler.strategy.ProcessingStrategy;
import io.contexa.contexacore.autonomous.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.redisson.api.RedissonClient;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.KafkaTemplate;

import java.util.List;

@AutoConfiguration
@AutoConfigureAfter(name = "io.contexa.autoconfigure.core.autonomous.CoreAutonomousAutoConfiguration")
@ConditionalOnProperty(prefix = "contexa.autonomous", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(SecurityPlaneProperties.class)
public class CoreAutonomousEventAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(KafkaTemplate.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    public KafkaSecurityEventCollector kafkaSecurityEventCollector(
            ObjectMapper objectMapper,
            KafkaTemplate<String, Object> kafkaTemplate,
            SecurityKafkaProperties securityKafkaProperties) {
        return new KafkaSecurityEventCollector(objectMapper, kafkaTemplate, securityKafkaProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(KafkaTemplate.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    public KafkaSecurityEventPublisher kafkaSecurityEventPublisher(
            KafkaTemplate<String, Object> kafkaTemplate,
            SecurityKafkaProperties securityKafkaProperties) {
        return new KafkaSecurityEventPublisher(kafkaTemplate, securityKafkaProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(RedissonClient.class)
    public BlockingDecisionRegistry blockingDecisionRegistry(RedissonClient redissonClient) {
        return new BlockingDecisionRegistry(redissonClient);
    }

    // === Standalone mode: In-memory event beans ===

    @Configuration
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
    static class StandaloneEventConfiguration {

        @Bean
        @ConditionalOnMissingBean(SecurityEventCollector.class)
        public InMemorySecurityEventCollector inMemorySecurityEventCollector() {
            return new InMemorySecurityEventCollector();
        }

        @Bean
        @ConditionalOnMissingBean(SecurityEventPublisher.class)
        public InMemorySecurityEventPublisher inMemorySecurityEventPublisher(
                SecurityEventCollector collector) {
            return new InMemorySecurityEventPublisher(collector);
        }

        @Bean
        @ConditionalOnMissingBean(BlockingSignalBroadcaster.class)
        public InMemoryBlockingSignalBroadcaster inMemoryBlockingSignalBroadcaster() {
            return new InMemoryBlockingSignalBroadcaster();
        }
    }

    // === Common beans (mode-independent) ===

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustEventListener zeroTrustEventListener(
            SecurityEventPublisher securityEventPublisher,
            ZeroTrustActionRepository actionRepository,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new ZeroTrustEventListener(securityEventPublisher, actionRepository, securityZeroTrustProperties);
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
    public LlmAnalysisEventListener llmAnalysisEventListener(ObjectProvider<List<LlmAnalysisEventObserver>> observersProvider) {
        return new CompositeLlmAnalysisEventListener(observersProvider.getIfAvailable(List::of));
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({Layer1ContextualStrategy.class, Layer2ExpertStrategy.class})
    public ColdPathEventProcessor coldPathEventProcessor(
            Layer1ContextualStrategy contextualStrategy,
            Layer2ExpertStrategy expertStrategy,
            LlmAnalysisEventListener llmAnalysisEventListener) {
        return new ColdPathEventProcessor(contextualStrategy, expertStrategy, llmAnalysisEventListener);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ColdPathEventProcessor.class)
    public ColdPathStrategy coldPathStrategy(ColdPathEventProcessor coldPathEventProcessor) {
        return new ColdPathStrategy(coldPathEventProcessor);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ProcessingStrategy.class)
    public ProcessingExecutionHandler processingExecutionHandler(
            List<ProcessingStrategy> processingStrategies) {
        return new ProcessingExecutionHandler(processingStrategies);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SecurityLearningService.class)
    public SecurityDecisionEnforcementHandler securityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRepository,
            SecurityLearningService securityLearningService) {
        return new SecurityDecisionEnforcementHandler(
                actionRepository, securityLearningService);
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskAssessment riskAssessment() {
        return new RiskAssessment();
    }
}

