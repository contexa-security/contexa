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
package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.statemachine.action.*;
import io.contexa.contexaidentity.security.statemachine.config.MfaStateMachineConfiguration;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.config.kyro.MfaKryoStateMachineSerialisationService;
import io.contexa.contexaidentity.security.statemachine.core.persist.ApplicationStateMachineKeyspaces;
import io.contexa.contexaidentity.security.statemachine.core.persist.ExpiringRedisRepositoryStateMachinePersist;
import io.contexa.contexaidentity.security.statemachine.core.persist.InMemoryStateMachinePersist;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineServiceImpl;
import io.contexa.contexaidentity.security.statemachine.core.service.StandaloneMfaStateMachineServiceImpl;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.guard.AllFactorsCompletedGuard;
import io.contexa.contexaidentity.security.statemachine.guard.BlockedUserGuard;
import io.contexa.contexaidentity.security.statemachine.guard.FactorSelectionTimeoutGuard;
import io.contexa.contexaidentity.security.statemachine.guard.RetryLimitGuard;
import io.contexa.contexaidentity.security.statemachine.listener.MfaStateChangeListener;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RedissonClient;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.NoneNestedConditions;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisKeyValueAdapter;
import org.springframework.data.redis.core.RedisKeyValueTemplate;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.convert.MappingConfiguration;
import org.springframework.data.redis.core.convert.MappingRedisConverter;
import org.springframework.data.redis.core.convert.RedisCustomConversions;
import org.springframework.data.redis.core.convert.ReferenceResolverImpl;
import org.springframework.data.redis.core.index.IndexConfiguration;
import org.springframework.data.redis.core.mapping.RedisMappingContext;
import org.springframework.data.redis.repository.support.RedisRepositoryFactory;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.data.redis.RedisPersistingStateMachineInterceptor;
import org.springframework.statemachine.data.redis.RedisRepositoryStateMachinePersist;
import org.springframework.statemachine.data.redis.RedisStateMachineRepository;
import org.springframework.statemachine.persist.DefaultStateMachinePersister;
import org.springframework.statemachine.persist.StateMachinePersister;

import java.time.Duration;
import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

@Slf4j
@AutoConfiguration
@AutoConfigureAfter(name = {
        "org.redisson.spring.starter.RedissonAutoConfiguration",
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
        "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration",
        "io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration"
})
@EnableConfigurationProperties(StateMachineProperties.class)
@ConditionalOnBean(PlatformConfig.class)
@ConditionalOnProperty(prefix = "contexa.identity.statemachine", name = "enabled", havingValue = "true", matchIfMissing = true)
@Import({
        MfaStateMachineConfiguration.class
})
public class IdentityStateMachineAutoConfiguration {

    /** Contexa's own Redisson client, which the distributed mode makes (RedissonConfiguration). */
    private static final String CONTEXA_REDISSON_CLIENT = "contexaRedissonClient";
    private static final String REDISSON_CLIENT = "org.redisson.api.RedissonClient";
    private static final String REDIS_STATE_MACHINE_REPOSITORY = "org.springframework.statemachine.data.redis.RedisStateMachineRepository";

    public IdentityStateMachineAutoConfiguration() {
    }

    @Bean(name = "contexaInitializeMfaAction")
    @ConditionalOnMissingBean
    public InitializeMfaAction initializeMfaAction(PlatformConfig platformConfig) {
        return new InitializeMfaAction(platformConfig);
    }

    @Bean(name = "contexaSelectFactorAction")
    @ConditionalOnMissingBean
    public SelectFactorAction selectFactorAction() {
        return new SelectFactorAction();
    }

    @Bean(name = "contexaInitiateChallengeAction")
    @ConditionalOnMissingBean
    public InitiateChallengeAction initiateChallengeAction() {
        return new InitiateChallengeAction();
    }

    @Bean(name = "contexaVerifyFactorAction")
    @ConditionalOnMissingBean
    public VerifyFactorAction verifyFactorAction(PlatformConfig platformConfig) {
        return new VerifyFactorAction(platformConfig);
    }

    @Bean(name = "contexaDetermineNextFactorAction")
    @ConditionalOnMissingBean
    public DetermineNextFactorAction determineNextFactorAction(MfaPolicyProvider policyProvider) {
        return new DetermineNextFactorAction(policyProvider);
    }

    @Bean(name = "contexaHandleFailureAction")
    @ConditionalOnMissingBean
    public HandleFailureAction handleFailureAction(AuthContextProperties authContextProperties) {
        return new HandleFailureAction(authContextProperties.getMfa());
    }

    @Bean(name = "contexaCompleteMfaAction")
    @ConditionalOnMissingBean
    public CompleteMfaAction completeMfaAction() {
        return new CompleteMfaAction();
    }

    @Bean(name = "contexaAllFactorsCompletedGuard")
    @ConditionalOnMissingBean
    public AllFactorsCompletedGuard allFactorsCompletedGuard(MfaPolicyProvider policyProvider) {
        return new AllFactorsCompletedGuard(policyProvider);
    }

    @Bean(name = "contexaBlockedUserGuard")
    @ConditionalOnMissingBean
    public BlockedUserGuard blockedUserGuard() {
        return new BlockedUserGuard();
    }

    @Bean(name = "contexaRetryLimitGuard")
    @ConditionalOnMissingBean
    public RetryLimitGuard retryLimitGuard(AuthContextProperties authContextProperties) {
        return new RetryLimitGuard(authContextProperties.getMfa());
    }

    @Bean(name = "contexaFactorSelectionTimeoutGuard")
    @ConditionalOnMissingBean
    public FactorSelectionTimeoutGuard factorSelectionTimeoutGuard() {
        return new FactorSelectionTimeoutGuard();
    }

    @Bean(name = "contexaMfaStateMachineIntegrator")
    @ConditionalOnMissingBean
    public MfaStateMachineIntegrator mfaStateMachineIntegrator(
            MfaStateMachineService contexaMfaStateMachineService,
            MfaSessionRepository contexaMfaSessionRepository,
            AuthContextProperties authContextProperties) {
        return new MfaStateMachineIntegrator(contexaMfaStateMachineService, contexaMfaSessionRepository, authContextProperties);
    }

    /** Z-16 (F6): a context lapses the persistence TTL after its last write, as in the Redis persist. */
    @Bean(name = "contexaInMemoryStateMachinePersist")
    @ConditionalOnMissingBean
    public InMemoryStateMachinePersist inMemoryStateMachinePersist(StateMachineProperties properties) {
        return new InMemoryStateMachinePersist(persistenceTtl(properties));
    }

    /** {@code contexa.identity.statemachine.persistence.ttl-minutes}, 30 minutes without it. */
    static Duration persistenceTtl(StateMachineProperties properties) {
        Integer minutes = properties.getPersistence() != null ? properties.getPersistence().getTtlMinutes() : null;
        return Duration.ofMinutes(minutes != null && minutes > 0 ? minutes : 30);
    }


    /**
     * The flows in Redis, on Contexa's own Redisson client. Whether an application has a Redisson client of its own decides
     * nothing here: the application's client is the application's, and Contexa neither uses it nor asks whether it exists.
     */
    @Configuration
    @ConditionalOnClass(name = {REDISSON_CLIENT, REDIS_STATE_MACHINE_REPOSITORY})
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    @ConditionalOnBean(name = CONTEXA_REDISSON_CLIENT)
    static class DistributedStateMachineConfig {

        /** The template Spring Data's Redis repositories take when they name none. */
        private static final String SPRING_DATA_REDIS_TEMPLATE = "redisTemplate";

        @Bean(name = "contexaMfaStateMachineService")
        @ConditionalOnMissingBean
        public MfaStateMachineService mfaStateMachineService(
                StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
                StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
                @Qualifier(CONTEXA_REDISSON_CLIENT) RedissonClient contexaRedissonClient,
                StateMachineProperties properties) {
            return new MfaStateMachineServiceImpl(
                    stateMachineFactory, stateMachinePersister, contexaRedissonClient, properties);
        }

        /**
         * The repository of the MFA flows in Redis. Enabling Spring Data's repositories for Spring Statemachine's package put
         * repository factories and Spring Data's beans in the application's context, and Spring Boot then made none of the
         * application's own Redis repositories. This repository is what that made, held by Contexa alone: the same keyspaces
         * (the application's name), mapping and conversions, on the template named redisTemplate that Spring Data's
         * repositories use when none is named, so a flow keeps its keys, its form and its Redis. The template is taken by its
         * name, as Spring Data refers to it, so one the application keeps from injection is found too, and it outlives the
         * repository at shutdown. The repository is no candidate for an injection point of the application.
         */
        @Bean(name = "contexaRedisStateMachineRepository", defaultCandidate = false)
        @ConditionalOnMissingBean(name = "contexaRedisStateMachineRepository")
        public RedisStateMachineRepository redisStateMachineRepository(ConfigurableBeanFactory beanFactory) {
            RedisOperations<?, ?> redisTemplate = beanFactory.getBean(SPRING_DATA_REDIS_TEMPLATE, RedisOperations.class);
            beanFactory.registerDependentBean(SPRING_DATA_REDIS_TEMPLATE, "contexaRedisStateMachineRepository");
            return stateMachineRepository(redisTemplate);
        }

        /** Z-16 (F6): a context lapses the persistence TTL after its last write, as in the in-memory persist. */
        @Bean(name = "contexaStateMachinePersist")
        @ConditionalOnMissingBean
        public RedisRepositoryStateMachinePersist<MfaState, MfaEvent> stateMachinePersist(
                @Qualifier("contexaRedisStateMachineRepository") RedisStateMachineRepository contexaRedisStateMachineRepository,
                StateMachineProperties properties) {
            return new ExpiringRedisRepositoryStateMachinePersist(contexaRedisStateMachineRepository,
                    new MfaKryoStateMachineSerialisationService(), persistenceTtl(properties));
        }

        /**
         * The objects Spring Data's repository configuration makes for {@code RedisStateMachineRepository}, with its defaults,
         * as objects of Contexa's: no keyspace events (no listener container, no shadow copies), and no events of the
         * template or the mapping published to the application.
         */
        static RedisStateMachineRepository stateMachineRepository(RedisOperations<?, ?> redisTemplate) {
            RedisMappingContext mappingContext = new RedisMappingContext(
                    new MappingConfiguration(new IndexConfiguration(), new ApplicationStateMachineKeyspaces()));
            mappingContext.afterPropertiesSet();

            MappingRedisConverter converter = new MappingRedisConverter(mappingContext);
            converter.setReferenceResolver(new ReferenceResolverImpl(redisTemplate));
            converter.setCustomConversions(new RedisCustomConversions());
            converter.afterPropertiesSet();

            RedisKeyValueAdapter adapter = new RedisKeyValueAdapter(redisTemplate, converter);
            adapter.setEnableKeyspaceEvents(RedisKeyValueAdapter.EnableKeyspaceEvents.OFF);
            adapter.setShadowCopy(RedisKeyValueAdapter.ShadowCopy.DEFAULT);

            return new RedisRepositoryFactory(new RedisKeyValueTemplate(adapter, mappingContext))
                    .getRepository(RedisStateMachineRepository.class);
        }

        @Bean(name = "contexaStateMachineRuntimePersister")
        @ConditionalOnMissingBean
        @SuppressWarnings({"rawtypes"})
        public StateMachinePersister<MfaState, MfaEvent, String> stateMachineRuntimePersister(
                RedisRepositoryStateMachinePersist<MfaState, MfaEvent> contexaStateMachinePersist) {
            return new DefaultStateMachinePersister(
                    new RedisPersistingStateMachineInterceptor<>(contexaStateMachinePersist));
        }
    }


    /**
     * The flows in memory, wherever the distributed store is not made: the two are decided by the same conditions, so one
     * of them is always made. An application's own Redisson client decided between them once, and with it in a standalone
     * application neither was made and the application did not start.
     */
    @Configuration
    @Conditional(WithoutDistributedStore.class)
    static class StandaloneStateMachineConfig {

        @Bean(name = "contexaStateMachineRuntimePersister")
        @ConditionalOnMissingBean
        public StateMachinePersister<MfaState, MfaEvent, String> stateMachineRuntimePersister(
                InMemoryStateMachinePersist persist) {
            return new DefaultStateMachinePersister<>(persist);
        }

        @Bean(name = "contexaMfaStateMachineService")
        @ConditionalOnMissingBean
        public MfaStateMachineService mfaStateMachineService(
                StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
                StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
                StateMachineProperties properties,
                InMemoryStateMachinePersist persist) {
            return new StandaloneMfaStateMachineServiceImpl(
                    stateMachineFactory, stateMachinePersister, properties, persist);
        }
    }

    /** Not every condition of the distributed store holds. */
    static class WithoutDistributedStore extends NoneNestedConditions {

        WithoutDistributedStore() {
            super(ConfigurationPhase.REGISTER_BEAN);
        }

        @ConditionalOnClass(name = {REDISSON_CLIENT, REDIS_STATE_MACHINE_REPOSITORY})
        @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
        @ConditionalOnBean(name = CONTEXA_REDISSON_CLIENT)
        static class DistributedStore {
        }
    }

    @Bean(name = "contexaMfaStateChangeListener")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.auth.mfa", name = "metrics-enabled", havingValue = "true", matchIfMissing = true)
    public MfaStateChangeListener mfaStateChangeListener() {
        return new MfaStateChangeListener();
    }

    @Bean(name = "contexaMfaEventExecutor", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaMfaEventExecutor")
    public Executor mfaEventExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(50);
        executor.setQueueCapacity(1000);
        executor.setThreadNamePrefix("mfa-event-");
        executor.setAllowCoreThreadTimeOut(true);

        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());

        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);

        executor.initialize();

        return executor;
    }

    @Bean(name = "contexaMonitoringExecutor", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaMonitoringExecutor")
    public Executor monitoringExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(5);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("monitoring-");
        executor.setAllowCoreThreadTimeOut(true);
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
        executor.initialize();

        return executor;
    }
}
