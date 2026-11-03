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
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
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
        "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration"
})
@EnableConfigurationProperties(StateMachineProperties.class)
@ConditionalOnBean(PlatformConfig.class)
@ConditionalOnProperty(prefix = "contexa.identity.statemachine", name = "enabled", havingValue = "true", matchIfMissing = true)
@Import({
        MfaStateMachineConfiguration.class
})
public class IdentityStateMachineAutoConfiguration {

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


    @Configuration
    @ConditionalOnClass(name = {
            "org.redisson.api.RedissonClient",
            "org.springframework.statemachine.data.redis.RedisStateMachineRepository"
    })
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    @ConditionalOnBean(type = "org.redisson.api.RedissonClient")
    @EnableRedisRepositories(basePackages = "org.springframework.statemachine.data.redis")
    static class DistributedStateMachineConfig {

        @Bean(name = "contexaMfaStateMachineService")
        @ConditionalOnMissingBean
        public MfaStateMachineService mfaStateMachineService(
                StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
                StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
                RedissonClient contexaRedissonClient,
                StateMachineProperties properties) {
            return new MfaStateMachineServiceImpl(
                    stateMachineFactory, stateMachinePersister, contexaRedissonClient, properties);
        }

        /** Z-16 (F6): a context lapses the persistence TTL after its last write, as in the in-memory persist. */
        @Bean(name = "contexaStateMachinePersist")
        @ConditionalOnMissingBean
        public RedisRepositoryStateMachinePersist<MfaState, MfaEvent> stateMachinePersist(
                RedisStateMachineRepository redisStateMachineRepository,
                StateMachineProperties properties) {
            return new ExpiringRedisRepositoryStateMachinePersist(redisStateMachineRepository,
                    new MfaKryoStateMachineSerialisationService(), persistenceTtl(properties));
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


    @Configuration
    @ConditionalOnMissingBean(type = "org.redisson.api.RedissonClient")
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
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
        executor.initialize();

        return executor;
    }
}
