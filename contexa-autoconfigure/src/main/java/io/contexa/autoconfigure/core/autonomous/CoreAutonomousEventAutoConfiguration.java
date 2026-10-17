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
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
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
import io.contexa.contexacore.autonomous.processor.PromptShadowRunner;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.UnanalysedRequestRecorder;
import io.contexa.contexacore.autonomous.service.DeletedAccountWriteFence;
import io.contexa.contexacore.autonomous.service.LearningPromotionService;
import io.contexa.contexacore.autonomous.service.VerificationLearningService;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
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
import java.util.Locale;
import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

@AutoConfiguration
@AutoConfigureAfter(name = {
        "io.contexa.autoconfigure.core.autonomous.CoreAutonomousAutoConfiguration",
        "io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration"
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
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
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
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ObjectProvider<UnanalysedRequestRecorder> unanalysedRequestRecorder) {
        ZeroTrustEventListener listener =
                new ZeroTrustEventListener(securityEventPublisher, actionRepository, securityZeroTrustProperties);
        listener.setUnanalysedRequestRecorder(unanalysedRequestRecorder.getIfAvailable());
        return listener;
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustEventPublisher zeroTrustEventPublisher(
            ApplicationEventPublisher applicationEventPublisher,
            TieredStrategyProperties tieredStrategyProperties,
            SecurityContextDataStore securityContextDataStore,
            SecurityPlaneProperties securityPlaneProperties) {
        return new ZeroTrustEventPublisher(
                applicationEventPublisher,
                tieredStrategyProperties,
                securityContextDataStore,
                securityPlaneProperties);
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
            LlmAnalysisEventListener llmAnalysisEventListener,
            ObjectProvider<PromptShadowRunner> promptShadowRunner) {
        ColdPathEventProcessor processor = new ColdPathEventProcessor(contextualStrategy, expertStrategy,
                llmAnalysisEventListener);
        // W6-9: the shadow run after the decision, when one is configured.
        processor.setShadowRunner(promptShadowRunner.getIfAvailable());
        return processor;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ColdPathEventProcessor.class)
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
            Environment environment) {
        return new AiSecurityDecisionObservationWriter(
                jdbcOperationsProvider::getIfAvailable,
                objectMapper,
                defaultModelProvider(environment),
                defaultModelId(environment));
    }

    private static String defaultModelProvider(Environment environment) {
        if (environment == null) {
            return null;
        }
        String chatProvider = chatProvider(environment);
        if (chatProvider != null) {
            return chatProvider;
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
        String chatProvider = chatProvider(environment);
        if (chatProvider != null) {
            return environment.getProperty("spring.ai." + chatProvider + ".chat.options.model");
        }
        return firstText(
                environment.getProperty("spring.ai.openai.chat.options.model"),
                environment.getProperty("spring.ai.anthropic.chat.options.model"),
                environment.getProperty("spring.ai.ollama.chat.options.model"));
    }

    /**
     * The chat provider Spring AI runs (spring.ai.model.chat) when its model is set; an application that can switch
     * providers may set another provider's model as well.
     */
    private static String chatProvider(Environment environment) {
        String configured = environment.getProperty("spring.ai.model.chat");
        if (!hasText(configured)) {
            return null;
        }
        String provider = configured.trim().toLowerCase(Locale.ROOT);
        return List.of("openai", "anthropic", "ollama").contains(provider)
                && hasText(environment.getProperty("spring.ai." + provider + ".chat.options.model")) ? provider : null;
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
            @Qualifier("securityBaselineLearningExecutor") ObjectProvider<Executor> baselineLearningExecutorProvider,
            ObjectProvider<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterProvider,
            SecurityContextDataStore securityContextDataStore,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ObjectProvider<ContextObservationRecorder> contextObservationRecorderProvider,
            ObjectProvider<VerificationLearningService> verificationLearningService,
            ObjectProvider<LearningPromotionService> learningPromotionService,
            ObjectProvider<DeletedAccountWriteFence> deletedAccountWriteFence) {
        SecurityDecisionEnforcementHandler handler = new SecurityDecisionEnforcementHandler(
                actionRepository,
                securityLearningService,
                blockedUserRecorder,
                blockingSignalBroadcaster,
                securityZeroTrustProperties,
                baselineLearningExecutorProvider.getIfAvailable(() -> command -> command.run()),
                aiSecurityDecisionObservationWriterProvider::getIfAvailable,
                securityContextDataStore,
                contextObservationRecorderProvider.getIfAvailable());
        handler.setVerificationLearningService(verificationLearningService.getIfAvailable());
        handler.setLearningPromotionService(learningPromotionService.getIfAvailable());
        handler.setDeletedAccountWriteFence(deletedAccountWriteFence.getIfAvailable());
        return handler;
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskAssessment riskAssessment() {
        return new RiskAssessment();
    }
}

