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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.SecurityEventProcessor;
import io.contexa.contexacore.autonomous.blocking.BlockingDecisionRegistry;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.RiskAssessment;
import io.contexa.contexacore.autonomous.event.*;
import io.contexa.contexacore.autonomous.event.listener.InMemorySecurityEventCollector;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.InMemorySecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.handler.handler.ProcessingExecutionHandler;
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.handler.strategy.ColdPathStrategy;
import io.contexa.contexacore.autonomous.handler.strategy.ProcessingStrategy;
import io.contexa.contexacore.autonomous.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.hcad.evaluation.HcadEvaluationWriter;
import io.contexa.contexacore.hcad.semantic.HcadSemanticEvidenceRefreshService;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.redisson.api.RedissonClient;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

@AutoConfiguration
@AutoConfigureAfter(name = {
        "io.contexa.autoconfigure.core.autonomous.CoreAutonomousAutoConfiguration",
        "io.contexa.autoconfigure.core.hcad.CoreHCADAutoConfiguration"
})
@ConditionalOnProperty(prefix = "contexa.autonomous", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({
        SecurityPlaneProperties.class,
        SecurityKafkaProperties.class,
        SecurityZeroTrustProperties.class,
        TieredStrategyProperties.class
})
public class CoreAutonomousEventAutoConfiguration {

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.kafka.core.KafkaTemplate")
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    static class KafkaEventConfiguration {

        @Bean
        @ConditionalOnMissingBean
        @ConditionalOnBean(type = "org.springframework.kafka.core.KafkaTemplate")
        public KafkaSecurityEventCollector kafkaSecurityEventCollector(
                ObjectMapper objectMapper,
                KafkaTemplate<String, Object> kafkaTemplate,
                SecurityKafkaProperties securityKafkaProperties) {
            return new KafkaSecurityEventCollector(objectMapper, kafkaTemplate, securityKafkaProperties);
        }

        @Bean
        @ConditionalOnMissingBean
        @ConditionalOnBean(type = "org.springframework.kafka.core.KafkaTemplate")
        public KafkaSecurityEventPublisher kafkaSecurityEventPublisher(
                KafkaTemplate<String, Object> kafkaTemplate,
                SecurityKafkaProperties securityKafkaProperties) {
            return new KafkaSecurityEventPublisher(kafkaTemplate, securityKafkaProperties);
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.redisson.api.RedissonClient")
    static class RedissonEventConfiguration {

        @Bean
        @ConditionalOnMissingBean
        @ConditionalOnBean(type = "org.redisson.api.RedissonClient")
        public BlockingDecisionRegistry blockingDecisionRegistry(RedissonClient redissonClient) {
            return new BlockingDecisionRegistry(redissonClient);
        }
    }

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
    public ColdPathStrategy coldPathStrategy(ColdPathEventProcessor coldPathEventProcessor) {
        return new ColdPathStrategy(coldPathEventProcessor);
    }

    @Bean
    @ConditionalOnMissingBean
    public ProcessingExecutionHandler processingExecutionHandler(
            List<ProcessingStrategy> processingStrategies) {
        return new ProcessingExecutionHandler(processingStrategies);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityEventProcessor securityEventProcessingOrchestrator(
            List<SecurityEventHandler> handlers,
            SecurityPlaneProperties securityPlaneProperties) {
        return new SecurityEventProcessor(handlers, securityPlaneProperties.getAgent().getName());
    }

    @Bean
    @ConditionalOnMissingBean(name = "securityBaselineLearningExecutor")
    public Executor securityBaselineLearningExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(2);
        executor.setQueueCapacity(500);
        executor.setThreadNamePrefix("Security-Baseline-Learning-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(60);
        executor.initialize();
        return executor;
    }

    @Bean
    @ConditionalOnMissingBean
    public AiSecurityDecisionObservationWriter aiSecurityDecisionObservationWriter(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider,
            ObjectMapper objectMapper,
            Environment environment,
            ObjectProvider<HcadSemanticEvidenceRefreshService> semanticEvidenceRefreshServiceProvider) {
        return new AiSecurityDecisionObservationWriter(
                jdbcOperationsProvider::getIfAvailable,
                objectMapper,
                defaultModelProvider(environment),
                defaultModelId(environment),
                semanticEvidenceRefreshServiceProvider.getIfAvailable());
    }

    private static String defaultModelProvider(Environment environment) {
        if (environment == null) {
            return null;
        }
        if (hasText(environment.getProperty("spring.ai.openai.chat.options.model"))) {
            return "openai";
        }
        if (hasText(environment.getProperty("spring.ai.anthropic.chat.options.model"))) {
            return "anthropic";
        }
        if (hasText(environment.getProperty("spring.ai.ollama.chat.options.model"))) {
            return "ollama";
        }
        return null;
    }

    private static String defaultModelId(Environment environment) {
        if (environment == null) {
            return null;
        }
        return firstText(
                environment.getProperty("spring.ai.openai.chat.options.model"),
                environment.getProperty("spring.ai.anthropic.chat.options.model"),
                environment.getProperty("spring.ai.ollama.chat.options.model"));
    }

    private static String firstText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SecurityLearningService.class)
    public SecurityDecisionEnforcementHandler securityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockingSignalBroadcaster blockingSignalBroadcaster,
            ObjectProvider<AnalysisTriggerStateRepository> analysisTriggerStateRepositoryProvider,
            @Qualifier("securityBaselineLearningExecutor") ObjectProvider<Executor> baselineLearningExecutorProvider,
            ObjectProvider<HcadEvaluationWriter> hcadEvaluationWriterProvider,
            ObjectProvider<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterProvider,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new SecurityDecisionEnforcementHandler(
                actionRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingSignalBroadcaster,
                analysisTriggerStateRepositoryProvider.getIfAvailable(),
                securityZeroTrustProperties,
                baselineLearningExecutorProvider.getIfAvailable(() -> command -> command.run()),
                hcadEvaluationWriterProvider.getIfAvailable(),
                aiSecurityDecisionObservationWriterProvider::getIfAvailable);
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskAssessment riskAssessment() {
        return new RiskAssessment();
    }
}

