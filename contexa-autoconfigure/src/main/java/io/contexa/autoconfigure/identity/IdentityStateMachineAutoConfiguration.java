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

/**
 * Identity StateMachine AutoConfiguration
 *
 * <p>
 * Contexa Identity의 StateMachine 관련 자동 구성을 제공합니다.
 * MFA StateMachine의 Action, Guard, Service, Persistence, Event 등을 명시적으로 등록합니다.
 * </p>
 *
 * <h3>포함된 Configuration:</h3>
 * <ul>
 *   <li>MfaStateMachineConfiguration - StateMachine DSL 설정 및 전이 정의 (@Import 유지 필수)</li>
 * </ul>
 *
 * <h3>등록되는 빈 (총 22개):</h3>
 * <ul>
 *   <li>Actions (7개): Initialize, Select, Initiate, Verify, Determine, Handle, Complete</li>
 *   <li>Guards (4개): AllFactorsCompleted, BlockedUser, RetryLimit, FactorSelectionTimeout</li>
 *   <li>Service (1개): MfaStateMachineServiceImpl</li>
 *   <li>Monitoring (2개): MfaStateMachineMonitorServiceImpl, AlertEventListener</li>
 *   <li>Integrator (2개): MfaStateMachineIntegrator, InMemoryStateMachinePersist</li>
 *   <li>Persistence (4개): stateMachinePersist, stateMachineRuntimePersister, mfaEventPublisher, mfaStateChangeListener</li>
 *   <li>Executors (2개): mfaEventExecutor, monitoringExecutor</li>
 * </ul>
 *
 * <h3>비동기 이벤트 처리:</h3>
 * <ul>
 *   <li>@EnableAsync - 비동기 이벤트 처리 활성화</li>
 *   <li>AsyncConfigurer - 기본 Executor 및 에러 핸들러 제공</li>
 *   <li>mfaEventExecutor - MFA 이벤트 전용 ThreadPool (코어 10, 최대 50, 큐 1000)</li>
 *   <li>monitoringExecutor - 모니터링 전용 ThreadPool (코어 2, 최대 5, 큐 100)</li>
 * </ul>
 *
 * <h3>활성화 조건:</h3>
 * <pre>
 * contexa:
 *   identity:
 *     statemachine:
 *       enabled: true  # (기본값)
 *       metrics-enabled: true  # MfaStateChangeListener 활성화 (기본값)
 * </pre>
 *
 * @since 0.1.0-ALPHA
 */
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

    // ========== Level 1: Actions (7개) ==========

    /**
     * 1-1. InitializeMfaAction - MFA 초기화 액션
     */
    @Bean
    @ConditionalOnMissingBean
    public InitializeMfaAction initializeMfaAction(PlatformConfig platformConfig) {
        return new InitializeMfaAction(platformConfig);
    }

    /**
     * 1-2. SelectFactorAction - 팩터 선택 액션
     */
    @Bean
    @ConditionalOnMissingBean
    public SelectFactorAction selectFactorAction() {
        return new SelectFactorAction();
    }

    /**
     * 1-3. InitiateChallengeAction - 챌린지 시작 액션
     */
    @Bean
    @ConditionalOnMissingBean
    public InitiateChallengeAction initiateChallengeAction() {
        return new InitiateChallengeAction();
    }

    /**
     * 1-4. VerifyFactorAction - 팩터 검증 액션
     */
    @Bean
    @ConditionalOnMissingBean
    public VerifyFactorAction verifyFactorAction(PlatformConfig platformConfig) {
        return new VerifyFactorAction(platformConfig);
    }

    /**
     * 1-5. DetermineNextFactorAction - 다음 팩터 결정 액션
     */
    @Bean
    @ConditionalOnMissingBean
    public DetermineNextFactorAction determineNextFactorAction(MfaPolicyProvider policyProvider) {
        return new DetermineNextFactorAction(policyProvider);
    }

    /**
     * 1-6. HandleFailureAction - 실패 처리 액션
     */
    @Bean
    @ConditionalOnMissingBean
    public HandleFailureAction handleFailureAction() {
        return new HandleFailureAction();
    }

    /**
     * 1-7. CompleteMfaAction - MFA 완료 액션
     */
    @Bean
    @ConditionalOnMissingBean
    public CompleteMfaAction completeMfaAction() {
        return new CompleteMfaAction();
    }

    // ========== Level 2: Guards (4개) ==========

    /**
     * 2-1. AllFactorsCompletedGuard - 모든 팩터 완료 검사 가드
     */
    @Bean
    @ConditionalOnMissingBean
    public AllFactorsCompletedGuard allFactorsCompletedGuard(MfaPolicyProvider policyProvider) {
        return new AllFactorsCompletedGuard(policyProvider);
    }

    /**
     * 2-2. BlockedUserGuard - 차단된 사용자 검사 가드
     */
    @Bean
    @ConditionalOnMissingBean
    public BlockedUserGuard blockedUserGuard() {
        return new BlockedUserGuard();
    }

    /**
     * 2-3. RetryLimitGuard - 재시도 제한 검사 가드
     */
    @Bean
    @ConditionalOnMissingBean
    public RetryLimitGuard retryLimitGuard() {
        return new RetryLimitGuard();
    }

    /**
     * 2-4. FactorSelectionTimeoutGuard - 팩터 선택 타임아웃 검사 가드
     */
    @Bean
    @ConditionalOnMissingBean
    public FactorSelectionTimeoutGuard factorSelectionTimeoutGuard() {
        return new FactorSelectionTimeoutGuard();
    }

    // ========== Level 3: Service (1개) ==========

    /**
     * 3-1. MfaStateMachineServiceImpl - MFA StateMachine 서비스
     */
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

    // ========== Level 4: Monitoring (2개) ==========

    /**
     * 4-1. MfaStateMachineMonitorServiceImpl - StateMachine 모니터링 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public MfaStateMachineMonitorService mfaStateMachineMonitorService(
            MeterRegistry meterRegistry,
            ApplicationEventPublisher eventPublisher) {
        return new MfaStateMachineMonitorServiceImpl(meterRegistry, eventPublisher);
    }

    /**
     * 4-2. AlertEventListener - 알림 이벤트 리스너
     */
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

    // ========== Level 5: Integrator & Persist (2개) ==========

    /**
     * 5-1. MfaStateMachineIntegrator - StateMachine 통합 컴포넌트
     */
    @Bean
    @ConditionalOnMissingBean
    public MfaStateMachineIntegrator mfaStateMachineIntegrator(
            MfaStateMachineService mfaStateMachineService,
            MfaSessionRepository mfaSessionRepository,
            AuthContextProperties authContextProperties) {
        return new MfaStateMachineIntegrator(mfaStateMachineService, mfaSessionRepository, authContextProperties);
    }

    /**
     * 5-2. InMemoryStateMachinePersist - 인메모리 StateMachine 영속화
     */
    @Bean
    @ConditionalOnMissingBean
    public InMemoryStateMachinePersist inMemoryStateMachinePersist() {
        return new InMemoryStateMachinePersist();
    }

    // ========== Level 6: Persistence & Event (4개) ==========

    /**
     * 6-1. stateMachinePersist - Redis 기반 StateMachine 영속화
     * <p>
     * Kryo 직렬화를 사용하여 StateMachine 상태를 Redis에 저장합니다.
     * </p>
     */
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

    /**
     * 6-2. stateMachineRuntimePersister - StateMachine 런타임 영속화 관리자
     * <p>
     * StateMachine의 상태를 저장하고 복원하는 Persister입니다.
     * Redis 기반 영속화 인터셉터를 통해 상태를 관리합니다.
     * </p>
     */
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

    /**
     * 6-3. mfaEventPublisher - MFA 이벤트 발행자
     * <p>
     * StateMachine 상태 변경 이벤트를 Spring ApplicationEventPublisher를 통해 발행합니다.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public MfaEventPublisher mfaEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        log.info("Creating MFA Event Publisher");
        return new MfaEventPublisher(applicationEventPublisher);
    }

    /**
     * 6-4. mfaStateChangeListener - MFA 상태 변경 리스너 (메트릭 수집용)
     * <p>
     * StateMachine 상태 변경을 감지하고 메트릭을 수집합니다.
     * spring.auth.mfa.metrics-enabled 설정으로 활성화/비활성화 가능합니다 (기본값: true).
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring.auth.mfa", name = "metrics-enabled", havingValue = "true", matchIfMissing = true)
    public MfaStateChangeListener mfaStateChangeListener() {
        log.info("Enabling MFA State Change Listener for metrics collection");
        return new MfaStateChangeListener();
    }

    // ========== Level 7: Async Executors (2개) ==========

    /**
     * 7-1. mfaEventExecutor - MFA 이벤트 처리 전용 Executor
     * <p>
     * MFA 이벤트를 비동기로 처리하기 위한 ThreadPoolTaskExecutor입니다.
     * </p>
     * <ul>
     *   <li>코어 스레드: 10</li>
     *   <li>최대 스레드: 50</li>
     *   <li>큐 용량: 1000</li>
     *   <li>거부 정책: CallerRunsPolicy (호출자 스레드에서 실행)</li>
     * </ul>
     */
    @Bean(name = "mfaEventExecutor")
    @ConditionalOnMissingBean(name = "mfaEventExecutor")
    public Executor mfaEventExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        // 스레드 풀 설정
        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(50);
        executor.setQueueCapacity(1000);
        executor.setThreadNamePrefix("mfa-event-");

        // 거부 정책: 호출자 스레드에서 실행
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());

        // 종료 시 작업 완료 대기
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);

        executor.initialize();

        log.info("MFA Event Executor initialized - Core: {}, Max: {}, Queue: {}",
                executor.getCorePoolSize(),
                executor.getMaxPoolSize(),
                executor.getQueueCapacity());

        return executor;
    }

    /**
     * 7-2. monitoringExecutor - 모니터링 전용 Executor
     * <p>
     * 모니터링 작업을 처리하기 위한 경량 ThreadPoolTaskExecutor입니다.
     * </p>
     * <ul>
     *   <li>코어 스레드: 2</li>
     *   <li>최대 스레드: 5</li>
     *   <li>큐 용량: 100</li>
     *   <li>거부 정책: DiscardPolicy (조용히 버림)</li>
     * </ul>
     */
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
