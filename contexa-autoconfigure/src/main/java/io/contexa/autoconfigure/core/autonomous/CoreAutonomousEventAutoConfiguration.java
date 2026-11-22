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
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.store.ContexaWorkCallerRunsPolicy;
import io.contexa.contexacore.autonomous.blocking.BlockedStateProbe;
import io.contexa.contexacore.autonomous.blocking.BlockingDecisionRegistry;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.RiskAssessment;
import io.contexa.contexacore.autonomous.event.*;
import io.contexa.contexacore.autonomous.event.listener.DecidedRecordAcknowledger;
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
import io.contexa.contexacore.autonomous.repository.ShadowDecisionMemory;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.NewContextDecisionLimit;
import io.contexa.contexacore.autonomous.service.UnanalysedRequestRecorder;
import io.contexa.contexacore.autonomous.service.DeletedAccountWriteFence;
import io.contexa.contexacore.autonomous.service.LearningPromotionService;
import io.contexa.contexacore.autonomous.service.VerificationLearningService;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustConsoleRetention;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustCoverageCounter;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustHourlyStats;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustReviewSampler;
import io.contexa.contexacore.autonomous.handler.handler.SealedEvidenceCaptureHandler;
import io.contexa.contexacore.verification.evidence.DecisionPriorityCaptureSampling;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.properties.SecurityColdPathProperties;
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

import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executor;
import io.contexa.contexacore.autonomous.agent.AgentAllowReuse;
import io.contexa.contexacore.autonomous.agent.AgentDecisionFlights;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.agent.AgentContainmentService;
import io.contexa.contexacore.autonomous.agent.AgentScopeNarrower;
import io.contexa.contexacore.autonomous.agent.AgentScopeService;
import io.contexa.contexacore.autonomous.agent.AgentScopeStore;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentScopeStore;
import io.contexa.contexacore.autonomous.agent.ReadOnlyAgentScopeNarrower;
import io.contexa.contexacore.autonomous.agent.AgentNotices;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexacore.autonomous.agent.AgentTokenRevoker;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.signal.RiskSignalEmitter;

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

        @Bean(name = "contexaKafkaSecurityEventCollector")
        @ConditionalOnMissingBean
        @ConditionalOnBean(name = "contexaKafkaTemplate")
        public KafkaSecurityEventCollector kafkaSecurityEventCollector(
                @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
                @Qualifier("contexaKafkaTemplate") KafkaTemplate<String, Object> contexaKafkaTemplate,
                SecurityKafkaProperties securityKafkaProperties,
                @Qualifier("contexaDecidedRecordAcknowledger") ObjectProvider<DecidedRecordAcknowledger> decidedRecords) {
            KafkaSecurityEventCollector collector =
                    new KafkaSecurityEventCollector(objectMapper, contexaKafkaTemplate, securityKafkaProperties);
            decidedRecords.ifAvailable(collector::setDecidedRecordAcknowledger);
            return collector;
        }

        @Bean(name = "contexaKafkaSecurityEventPublisher")
        @ConditionalOnMissingBean
        @ConditionalOnBean(name = "contexaKafkaTemplate")
        public KafkaSecurityEventPublisher kafkaSecurityEventPublisher(
                @Qualifier("contexaKafkaTemplate") KafkaTemplate<String, Object> contexaKafkaTemplate,
                SecurityKafkaProperties securityKafkaProperties,
                ObjectProvider<KafkaSecurityEventCollector> kafkaSecurityEventCollector,
                ObjectProvider<ZeroTrustCoverageCounter> coverageCounter) {
            KafkaSecurityEventPublisher publisher =
                    new KafkaSecurityEventPublisher(contexaKafkaTemplate, securityKafkaProperties);
            publisher.setCoverageCounter(coverageCounter.getIfAvailable());
            // Q-26: what Kafka does not take is analysed on this node.
            publisher.setLocalAnalysis(event -> kafkaSecurityEventCollector.ifAvailable(
                    collector -> collector.analyseHere(event)));
            return publisher;
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.redisson.api.RedissonClient")
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    static class RedissonEventConfiguration {

        /** On Contexa's own Redisson client: an application's own client carries none of Contexa's signals. */
        @Bean(name = "contexaBlockingDecisionRegistry")
        @ConditionalOnMissingBean
        @ConditionalOnBean(name = "contexaRedissonClient")
        public BlockingDecisionRegistry blockingDecisionRegistry(
                @Qualifier("contexaRedissonClient") RedissonClient contexaRedissonClient,
                ObjectProvider<ZeroTrustActionRepository> decisions) {
            return new BlockingDecisionRegistry(contexaRedissonClient, decisionInForce(decisions));
        }
    }

    @Bean(name = "contexaInMemorySecurityEventCollector")
    @ConditionalOnMissingBean(SecurityEventCollector.class)
    public InMemorySecurityEventCollector inMemorySecurityEventCollector() {
        return new InMemorySecurityEventCollector();
    }

    @Bean(name = "contexaInMemorySecurityEventPublisher")
    @ConditionalOnMissingBean(SecurityEventPublisher.class)
    public InMemorySecurityEventPublisher inMemorySecurityEventPublisher(
            SecurityEventCollector collector) {
        return new InMemorySecurityEventPublisher(collector);
    }

    @Bean(name = "contexaInMemoryBlockingSignalBroadcaster")
    @ConditionalOnMissingBean(BlockingSignalBroadcaster.class)
    public InMemoryBlockingSignalBroadcaster inMemoryBlockingSignalBroadcaster(
            ObjectProvider<ZeroTrustActionRepository> decisions) {
        return new InMemoryBlockingSignalBroadcaster(decisionInForce(decisions));
    }

    /** Reads the decision in force, so a BLOCK whose signal was missed still cuts a response in flight. */
    static BlockedStateProbe decisionInForce(ObjectProvider<ZeroTrustActionRepository> decisions) {
        return userId -> {
            ZeroTrustActionRepository repository = decisions.getIfAvailable();
            return repository != null && repository.getCurrentAction(userId, null) == ZeroTrustAction.BLOCK;
        };
    }


    /**
     * How many decisions of a new context a person may ask for in a short window on this server, sign-ins and calls from
     * a changed context together: contexa.security.zerotrust.analysis.new-context-limit.*.
     */
    @Bean(name = "contexaNewContextDecisionLimit")
    @ConditionalOnMissingBean
    public NewContextDecisionLimit newContextDecisionLimit(SecurityZeroTrustProperties securityZeroTrustProperties,
                                                           ObjectProvider<CentralAuditFacade> centralAuditFacade) {
        return new NewContextDecisionLimit(securityZeroTrustProperties.getAnalysis().getNewContextLimit(),
                centralAuditFacade.getIfAvailable(), null);
    }

    @Bean(name = "contexaZeroTrustEventListener")
    @ConditionalOnMissingBean
    public ZeroTrustEventListener zeroTrustEventListener(
            SecurityEventPublisher securityEventPublisher,
            ZeroTrustActionRepository actionRepository,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ObjectProvider<UnanalysedRequestRecorder> unanalysedRequestRecorder,
            ObjectProvider<ShadowDecisionMemory> shadowMemory,
            ObjectProvider<ZeroTrustCoverageCounter> coverageCounter) {
        ZeroTrustEventListener listener = new ZeroTrustEventListener(securityEventPublisher,
                ShadowDecisionMemory.answersOf(shadowMemory.getIfAvailable(), actionRepository), securityZeroTrustProperties);
        listener.setUnanalysedRequestRecorder(unanalysedRequestRecorder.getIfAvailable());
        listener.setCoverageCounter(coverageCounter.getIfAvailable());
        return listener;
    }

    /** docs/agent F-1: how far an ALLOW in force answers an agent's later requests without a new decision. */
    @Bean(name = "contexaAgentAllowReuse")
    @ConditionalOnMissingBean
    public AgentAllowReuse agentAllowReuse(SecurityZeroTrustProperties securityZeroTrustProperties) {
        SecurityZeroTrustProperties.AllowReuse settings = securityZeroTrustProperties.getAgent().getAllowReuse();
        return new AgentAllowReuse(settings.getMaxRequests(), settings.getMaxDistinctResources(),
                settings.getSensitiveMaxDistinctResources(), null);
    }

    /**
     * docs/agent RL-12: one agent's requests that come in numbers are analysed once per question, under a limit of
     * analyses running at once. contexa.security.zerotrust.agent.flight.*; off by default.
     */
    @Bean(name = "contexaAgentDecisionFlights")
    @ConditionalOnMissingBean
    public AgentDecisionFlights agentDecisionFlights(SecurityZeroTrustProperties securityZeroTrustProperties) {
        SecurityZeroTrustProperties.Flight settings = securityZeroTrustProperties.getAgent().getFlight();
        Set<ActionFamily> passFamilies = EnumSet.noneOf(ActionFamily.class);
        for (String name : settings.getPassFamilies()) {
            ActionFamily family = ActionFamily.of(name);
            if (family != null && family != ActionFamily.UNKNOWN) {
                passFamilies.add(family);
            }
        }
        return new AgentDecisionFlights(new AgentDecisionFlights.Settings(settings.isEnabled(),
                settings.getMaxInFlightAnalyses(), settings.getQueueCapacity(), settings.getWait(),
                settings.getPassBudget(), passFamilies));
    }

    @Bean(name = "contexaZeroTrustEventPublisher")
    @ConditionalOnMissingBean
    public ZeroTrustEventPublisher zeroTrustEventPublisher(
            ApplicationEventPublisher applicationEventPublisher,
            TieredStrategyProperties tieredStrategyProperties,
            SecurityContextDataStore securityContextDataStore,
            SecurityPlaneProperties securityPlaneProperties,
            ObjectProvider<ShadowDecisionMemory> shadowMemory) {
        ZeroTrustEventPublisher publisher = new ZeroTrustEventPublisher(
                applicationEventPublisher,
                tieredStrategyProperties,
                securityContextDataStore,
                securityPlaneProperties);
        shadowMemory.ifAvailable(memory -> publisher.setDecisionMemory(memory.answers()));
        return publisher;
    }

    @Bean(name = "contexaLlmAnalysisEventListener")
    @ConditionalOnMissingBean
    public LlmAnalysisEventListener llmAnalysisEventListener(ObjectProvider<List<LlmAnalysisEventObserver>> observersProvider) {
        return new CompositeLlmAnalysisEventListener(observersProvider.getIfAvailable(List::of));
    }

    @Bean(name = "contexaColdPathEventProcessor")
    @ConditionalOnMissingBean
    @ConditionalOnBean({Layer1ContextualStrategy.class, Layer2ExpertStrategy.class})
    public ColdPathEventProcessor coldPathEventProcessor(
            Layer1ContextualStrategy contexaContextualStrategy,
            Layer2ExpertStrategy contexaExpertStrategy,
            LlmAnalysisEventListener contexaLlmAnalysisEventListener,
            ObjectProvider<PromptShadowRunner> promptShadowRunner,
            ObjectProvider<SecurityColdPathProperties> securityColdPathProperties) {
        ColdPathEventProcessor processor = new ColdPathEventProcessor(contexaContextualStrategy, contexaExpertStrategy,
                contexaLlmAnalysisEventListener);
        // W6-9: the shadow run after the decision, when one is configured.
        processor.setShadowRunner(promptShadowRunner.getIfAvailable());
        // QF-42: the bound on escalation protection windows.
        SecurityColdPathProperties coldPath = securityColdPathProperties.getIfAvailable();
        if (coldPath != null) {
            processor.setMaxEscalationWindows(coldPath.getMaxEscalationWindows());
        }
        return processor;
    }

    @Bean(name = "contexaColdPathStrategy")
    @ConditionalOnMissingBean
    @ConditionalOnBean(ColdPathEventProcessor.class)
    public ColdPathStrategy coldPathStrategy(ColdPathEventProcessor contexaColdPathEventProcessor) {
        return new ColdPathStrategy(contexaColdPathEventProcessor);
    }

    @Bean(name = "contexaProcessingExecutionHandler")
    @ConditionalOnMissingBean
    public ProcessingExecutionHandler processingExecutionHandler(
            List<ProcessingStrategy> processingStrategies) {
        return new ProcessingExecutionHandler(processingStrategies);
    }

    @Bean(name = "contexaSecurityEventProcessingOrchestrator")
    @ConditionalOnMissingBean
    public SecurityEventProcessor securityEventProcessingOrchestrator(
            List<SecurityEventHandler> handlers,
            SecurityPlaneProperties securityPlaneProperties) {
        return new SecurityEventProcessor(handlers, securityPlaneProperties.getAgent().getName());
    }

    @Bean(name = "contexaSecurityBaselineLearningExecutor", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaSecurityBaselineLearningExecutor")
    public Executor securityBaselineLearningExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(2);
        executor.setQueueCapacity(500);
        executor.setThreadNamePrefix("contexa-security-baseline-learning-");
        executor.setAllowCoreThreadTimeOut(true);
        executor.setRejectedExecutionHandler(new ContexaWorkCallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(60);
        executor.initialize();
        return executor;
    }

    @Bean(name = "contexaAiSecurityDecisionObservationWriter")
    @ConditionalOnMissingBean
    public AiSecurityDecisionObservationWriter aiSecurityDecisionObservationWriter(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
            Environment environment) {
        return new AiSecurityDecisionObservationWriter(
                jdbcOperationsProvider::getIfAvailable,
                objectMapper,
                defaultModelProvider(environment),
                defaultModelId(environment));
    }

    /**
     * Console design 7.5: this node's counts of the protected calls, the calls a decision in force answered and the
     * calls the analysis skipped, under the node's host name.
     */
    @Bean(name = "contexaZeroTrustCoverageCounter")
    @ConditionalOnMissingBean
    public ZeroTrustCoverageCounter zeroTrustCoverageCounter(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider) {
        return new ZeroTrustCoverageCounter(jdbcOperationsProvider::getIfAvailable, ZeroTrustCoverageCounter.hostNodeId(),
                null);
    }

    /** Console design 7.3: what became of a decision afterwards (step-up, release, review). */
    @Bean(name = "contexaZeroTrustDecisionOutcomes")
    @ConditionalOnMissingBean
    public ZeroTrustDecisionOutcomes zeroTrustDecisionOutcomes(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider) {
        return new ZeroTrustDecisionOutcomes(jdbcOperationsProvider::getIfAvailable);
    }

    /** Console design 7.4 and 7.5: the hourly decision table, and the coverage counts each node adds. */
    @Bean(name = "contexaZeroTrustHourlyStats")
    @ConditionalOnMissingBean
    public ZeroTrustHourlyStats zeroTrustHourlyStats(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ObjectProvider<ZeroTrustCoverageCounter> coverageCounter) {
        return new ZeroTrustHourlyStats(jdbcOperationsProvider::getIfAvailable, securityZeroTrustProperties,
                coverageCounter.getIfAvailable(), null);
    }

    /** Console design 7.6: the decision rows and the aggregates past their retention go. */
    @Bean(name = "contexaZeroTrustConsoleRetention")
    @ConditionalOnMissingBean
    public ZeroTrustConsoleRetention zeroTrustConsoleRetention(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new ZeroTrustConsoleRetention(jdbcOperationsProvider::getIfAvailable, securityZeroTrustProperties, null);
    }

    /**
     * Console decision 11.3, quality plan 3.6: the decisions of a day an administrator is asked to review: the stopped
     * ones, and the allowed ones by risk and at random. The signs of risk are those the sealing of allowed decisions
     * chooses by, with its threshold of unknown facts; while the sealed evidence capture runs, only sealed decisions
     * are drawn.
     */
    @Bean(name = "contexaZeroTrustReviewSampler")
    @ConditionalOnMissingBean
    public ZeroTrustReviewSampler zeroTrustReviewSampler(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider,
            SecurityZeroTrustProperties securityZeroTrustProperties, Environment environment,
            ObjectProvider<SealedEvidenceCaptureHandler> captureHandler) {
        Integer threshold = environment.getProperty(UNKNOWN_FACT_THRESHOLD, Integer.class,
                DecisionPriorityCaptureSampling.DEFAULT_UNKNOWN_FACT_THRESHOLD);
        return new ZeroTrustReviewSampler(jdbcOperationsProvider::getIfAvailable, securityZeroTrustProperties, null,
                threshold, () -> captureHandler.getIfAvailable() != null);
    }

    /** The threshold of unknown facts the sealing of allowed decisions uses (PqaOssSealedEvidenceCaptureProperties). */
    static final String UNKNOWN_FACT_THRESHOLD = "contexa.pqa.oss.sealed-evidence.unknown-fact-threshold";

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

    @Bean(name = "contexaSecurityDecisionEnforcementHandler")
    @ConditionalOnMissingBean
    @ConditionalOnBean(SecurityLearningService.class)
    public SecurityDecisionEnforcementHandler securityDecisionEnforcementHandler(
            ZeroTrustActionRepository actionRepository,
            SecurityLearningService contexaSecurityLearningService,
            IBlockedUserRecorder contexaBlockedUserRecorder,
            BlockingSignalBroadcaster blockingSignalBroadcaster,
            @Qualifier("contexaSecurityBaselineLearningExecutor") ObjectProvider<Executor> baselineLearningExecutorProvider,
            ObjectProvider<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterProvider,
            SecurityContextDataStore securityContextDataStore,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ObjectProvider<ContextObservationRecorder> contextObservationRecorderProvider,
            ObjectProvider<VerificationLearningService> verificationLearningService,
            ObjectProvider<LearningPromotionService> learningPromotionService,
            ObjectProvider<DeletedAccountWriteFence> deletedAccountWriteFence,
            ObjectProvider<AgentContainmentService> agentContainment,
            ObjectProvider<AgentScopeService> agentScopes,
            ObjectProvider<RiskSignalEmitter> riskSignalEmitters,
            TieredStrategyProperties tieredStrategyProperties,
            ObjectProvider<ShadowDecisionMemory> shadowMemory) {
        SecurityDecisionEnforcementHandler handler = new SecurityDecisionEnforcementHandler(
                actionRepository,
                contexaSecurityLearningService,
                contexaBlockedUserRecorder,
                blockingSignalBroadcaster,
                securityZeroTrustProperties,
                baselineLearningExecutorProvider.getIfAvailable(() -> command -> command.run()),
                aiSecurityDecisionObservationWriterProvider::getIfAvailable,
                securityContextDataStore,
                contextObservationRecorderProvider.getIfAvailable());
        // SHADOW decides as ENFORCE does and applies nothing: what it decided is kept where only the counting reads it.
        shadowMemory.ifAvailable(memory -> handler.setShadowMemory(memory.remembers()));
        handler.setVerificationLearningService(verificationLearningService.getIfAvailable());
        handler.setLearningPromotionService(learningPromotionService.getIfAvailable());
        handler.setDeletedAccountWriteFence(deletedAccountWriteFence.getIfAvailable());
        // docs/agent A5-3: a BLOCK on an agent's request stops that agent.
        handler.setAgentContainment(agentContainment.getIfAvailable());
        // docs/agent A5-4: a decision on an agent's request may narrow its later requests.
        handler.setAgentScopes(agentScopes.getIfAvailable());
        // docs/agent A5-8: the host's emitters of risk level changes, none by default.
        handler.setRiskSignalEmitters(riskSignalEmitters.orderedStream().toList());
        // What a result that names no final action ends as, the Layer2 terminal policy.
        handler.setEscalateTerminalAction(tieredStrategyProperties.getLayer2().escalateTerminalAction());
        return handler;
    }

    /**
     * docs/agent A5-4: the default narrowing, to reading for a period after a risky decision on an agent's request
     * ({@code contexa.security.zerotrust.agent.scope-narrowing}); off, nothing is narrowed. An application declares
     * its own {@link AgentScopeNarrower} to narrow otherwise.
     */
    @Bean(name = "contexaAgentScopeNarrower")
    @ConditionalOnMissingBean(AgentScopeNarrower.class)
    public AgentScopeNarrower agentScopeNarrower(SecurityZeroTrustProperties securityZeroTrustProperties) {
        SecurityZeroTrustProperties.ScopeNarrowing settings = securityZeroTrustProperties.getAgent().getScopeNarrowing();
        return settings.isEnabled()
                ? new ReadOnlyAgentScopeNarrower(settings.getDuration(), settings.getRiskThreshold())
                : (subject, event, result) -> Optional.empty();
    }

    @Bean(name = "contexaAgentScopeService")
    @ConditionalOnMissingBean
    public AgentScopeService agentScopeService(ObjectProvider<AgentScopeStore> agentScopeStore,
                                               AgentScopeNarrower contexaAgentScopeNarrower,
                                               ObjectProvider<CentralAuditFacade> auditFacade) {
        return new AgentScopeService(agentScopeStore.getIfAvailable(InMemoryAgentScopeStore::new), contexaAgentScopeNarrower,
                auditFacade.getIfAvailable(), null);
    }

    /**
     * docs/agent A5-3: stops and releases agents: the delegation and tokens of an agent a BLOCK stopped, the agent's
     * suspension, the kill switch, and the notice to the accountable person.
     */
    @Bean(name = "contexaAgentContainmentService")
    @ConditionalOnMissingBean
    public AgentContainmentService agentContainmentService(ZeroTrustActionRepository actionRepository,
                                                           ObjectProvider<AgentRegistry> agentRegistry,
                                                           ObjectProvider<DelegationRegistry> delegationRegistry,
                                                           ObjectProvider<AgentTokenRevoker> agentTokenRevoker,
                                                           ObjectProvider<AgentNotices> agentNotices,
                                                           ObjectProvider<CentralAuditFacade> auditFacade) {
        return new AgentContainmentService(actionRepository, agentRegistry.getIfAvailable(),
                delegationRegistry.getIfAvailable(), agentTokenRevoker.getIfAvailable(),
                agentNotices.getIfAvailable(), auditFacade.getIfAvailable());
    }

    @Bean(name = "contexaRiskAssessment")
    @ConditionalOnMissingBean
    public RiskAssessment riskAssessment() {
        return new RiskAssessment();
    }
}

