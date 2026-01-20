package io.contexa.autoconfigure.identity;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.statemachine.action.*;
import io.contexa.contexaidentity.security.statemachine.config.MfaStateMachineConfiguration;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.config.kyro.MfaKryoStateMachineSerialisationService;
import io.contexa.contexaidentity.security.statemachine.core.event.MfaEventPublisher;
import io.contexa.contexaidentity.security.statemachine.core.persist.InMemoryStateMachinePersist;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineServiceImpl;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.guard.AllFactorsCompletedGuard;
import io.contexa.contexaidentity.security.statemachine.guard.BlockedUserGuard;
import io.contexa.contexaidentity.security.statemachine.guard.FactorSelectionTimeoutGuard;
import io.contexa.contexaidentity.security.statemachine.guard.RetryLimitGuard;
import io.contexa.contexaidentity.security.statemachine.listener.MfaStateChangeListener;
import io.contexa.contexaidentity.security.statemachine.monitoring.AlertEventListener;
import io.contexa.contexaidentity.security.statemachine.monitoring.MfaStateMachineMonitorService;
import io.contexa.contexaidentity.security.statemachine.monitoring.MfaStateMachineMonitorServiceImpl;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RedissonClient;
import org.springframework.aop.interceptor.AsyncUncaughtExceptionHandler;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.AsyncConfigurer;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.data.redis.RedisPersistingStateMachineInterceptor;
import org.springframework.statemachine.data.redis.RedisRepositoryStateMachinePersist;
import org.springframework.statemachine.data.redis.RedisStateMachineRepository;
import org.springframework.statemachine.persist.DefaultStateMachinePersister;
import org.springframework.statemachine.persist.StateMachinePersister;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;


@Slf4j
@AutoConfiguration
@EnableAsync
@EnableConfigurationProperties(StateMachineProperties.class)
@ConditionalOnProperty(
    prefix = "contexa.identity.statemachine",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@Import({
    MfaStateMachineConfiguration.class
})
public class IdentityStateMachineAutoConfiguration{

    public IdentityStateMachineAutoConfiguration() {
        log.info("IdentityStateMachineAutoConfiguration initialized - 22 beans registered");
    }

    

    
    @Bean
    @ConditionalOnMissingBean
    public InitializeMfaAction initializeMfaAction(PlatformConfig platformConfig) {
        return new InitializeMfaAction(platformConfig);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public SelectFactorAction selectFactorAction() {
        return new SelectFactorAction();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public InitiateChallengeAction initiateChallengeAction() {
        return new InitiateChallengeAction();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public VerifyFactorAction verifyFactorAction(PlatformConfig platformConfig) {
        return new VerifyFactorAction(platformConfig);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public DetermineNextFactorAction determineNextFactorAction(MfaPolicyProvider policyProvider) {
        return new DetermineNextFactorAction(policyProvider);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public HandleFailureAction handleFailureAction() {
        return new HandleFailureAction();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public CompleteMfaAction completeMfaAction() {
        return new CompleteMfaAction();
    }

    

    
    @Bean
    @ConditionalOnMissingBean
    public AllFactorsCompletedGuard allFactorsCompletedGuard(MfaPolicyProvider policyProvider) {
        return new AllFactorsCompletedGuard(policyProvider);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public BlockedUserGuard blockedUserGuard() {
        return new BlockedUserGuard();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public RetryLimitGuard retryLimitGuard() {
        return new RetryLimitGuard();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public FactorSelectionTimeoutGuard factorSelectionTimeoutGuard() {
        return new FactorSelectionTimeoutGuard();
    }

    

    
    @Bean
    @ConditionalOnMissingBean
    public MfaStateMachineService mfaStateMachineService(
            StateMachineFactory<MfaState, MfaEvent> stateMachineFactory,
            StateMachinePersister<MfaState, MfaEvent, String> stateMachinePersister,
            RedissonClient redissonClient,
            StateMachineProperties properties) {
        return new MfaStateMachineServiceImpl(
            stateMachineFactory, stateMachinePersister, redissonClient, properties
        );
    }

    

    
    @Bean
    @ConditionalOnMissingBean
    public MfaStateMachineMonitorService mfaStateMachineMonitorService(
            MeterRegistry meterRegistry,
            ApplicationEventPublisher eventPublisher) {
        return new MfaStateMachineMonitorServiceImpl(meterRegistry, eventPublisher);
    }

    
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.identity.statemachine",
        name = "alert-enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public AlertEventListener alertEventListener() {
        return new AlertEventListener();
    }

    

    
    @Bean
    @ConditionalOnMissingBean
    public MfaStateMachineIntegrator mfaStateMachineIntegrator(
            MfaStateMachineService mfaStateMachineService,
            MfaSessionRepository mfaSessionRepository,
            AuthContextProperties authContextProperties) {
        return new MfaStateMachineIntegrator(mfaStateMachineService, mfaSessionRepository, authContextProperties);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public InMemoryStateMachinePersist inMemoryStateMachinePersist() {
        return new InMemoryStateMachinePersist();
    }

    

    
    @Bean
    @ConditionalOnMissingBean
    @SuppressWarnings({"rawtypes"})
    public RedisRepositoryStateMachinePersist<MfaState, MfaEvent> stateMachinePersist(
            RedisStateMachineRepository redisStateMachineRepository) {
        MfaKryoStateMachineSerialisationService kryoStateMachineSerialisationService =
                new MfaKryoStateMachineSerialisationService();
        log.info("Creating RedisRepositoryStateMachinePersist with Kryo serialization");
        return new RedisRepositoryStateMachinePersist(redisStateMachineRepository, kryoStateMachineSerialisationService);
    }

    
    @Bean
    @ConditionalOnMissingBean
    @SuppressWarnings({"rawtypes"})
    public StateMachinePersister<MfaState, MfaEvent, String> stateMachineRuntimePersister(
            RedisRepositoryStateMachinePersist<MfaState, MfaEvent> stateMachinePersist) {
        RedisPersistingStateMachineInterceptor<MfaState, MfaEvent, Object> stateMachineInterceptor
                = new RedisPersistingStateMachineInterceptor<>(stateMachinePersist);
        log.info("Creating DefaultStateMachinePersister with Redis interceptor");
        return new DefaultStateMachinePersister(stateMachineInterceptor);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public MfaEventPublisher mfaEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        log.info("Creating MFA Event Publisher");
        return new MfaEventPublisher(applicationEventPublisher);
    }

    
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring.auth.mfa", name = "metrics-enabled", havingValue = "true", matchIfMissing = true)
    public MfaStateChangeListener mfaStateChangeListener() {
        log.info("Enabling MFA State Change Listener for metrics collection");
        return new MfaStateChangeListener();
    }

    

    
    @Bean(name = "mfaEventExecutor")
    @ConditionalOnMissingBean(name = "mfaEventExecutor")
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

        log.info("MFA Event Executor initialized - Core: {}, Max: {}, Queue: {}",
                executor.getCorePoolSize(),
                executor.getMaxPoolSize(),
                executor.getQueueCapacity());

        return executor;
    }

    
    @Bean(name = "monitoringExecutor")
    @ConditionalOnMissingBean(name = "monitoringExecutor")
    public Executor monitoringExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(5);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("monitoring-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
        executor.initialize();

        log.info("Monitoring Executor initialized - Core: {}, Max: {}, Queue: {}",
                executor.getCorePoolSize(),
                executor.getMaxPoolSize(),
                executor.getQueueCapacity());

        return executor;
    }
}
