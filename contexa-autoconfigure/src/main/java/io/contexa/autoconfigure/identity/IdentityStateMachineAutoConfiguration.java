package io.contexa.autoconfigure.identity;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.statemachine.action.*;
import io.contexa.contexaidentity.security.statemachine.config.MfaStateMachineConfiguration;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.config.UnifiedStateMachineConfiguration;
import io.contexa.contexaidentity.security.statemachine.core.persist.InMemoryStateMachinePersist;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineServiceImpl;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.guard.AllFactorsCompletedGuard;
import io.contexa.contexaidentity.security.statemachine.guard.BlockedUserGuard;
import io.contexa.contexaidentity.security.statemachine.guard.FactorSelectionTimeoutGuard;
import io.contexa.contexaidentity.security.statemachine.guard.RetryLimitGuard;
import io.contexa.contexaidentity.security.statemachine.monitoring.AlertEventListener;
import io.contexa.contexaidentity.security.statemachine.monitoring.MfaStateMachineMonitorService;
import io.contexa.contexaidentity.security.statemachine.monitoring.MfaStateMachineMonitorServiceImpl;
import io.micrometer.core.instrument.MeterRegistry;
import org.redisson.api.RedissonClient;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.persist.StateMachinePersister;

/**
 * Identity StateMachine AutoConfiguration
 *
 * <p>
 * Contexa Identity의 StateMachine 관련 자동 구성을 제공합니다.
 * MFA StateMachine의 Action, Guard, Service, Integrator 등을 명시적으로 등록합니다.
 * </p>
 *
 * <h3>포함된 Configuration:</h3>
 * <ul>
 *   <li>MfaStateMachineConfiguration - StateMachine 설정 및 전이 정의</li>
 *   <li>UnifiedStateMachineConfiguration - Redis 영속화, EventPublisher, StateChangeListener</li>
 * </ul>
 *
 * <h3>등록되는 빈:</h3>
 * <ul>
 *   <li>Actions (7개): Initialize, Select, Initiate, Verify, Determine, Handle, Complete</li>
 *   <li>Guards (4개): AllFactorsCompleted, BlockedUser, RetryLimit, FactorSelectionTimeout</li>
 *   <li>Service: MfaStateMachineServiceImpl</li>
 *   <li>Monitor: MfaStateMachineMonitorServiceImpl, AlertEventListener</li>
 *   <li>Integrator: MfaStateMachineIntegrator</li>
 *   <li>Persist: InMemoryStateMachinePersist</li>
 * </ul>
 *
 * <h3>활성화 조건:</h3>
 * <pre>
 * contexa:
 *   identity:
 *     statemachine:
 *       enabled: true  # (기본값)
 * </pre>
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.identity.statemachine",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@Import({
    MfaStateMachineConfiguration.class,
    UnifiedStateMachineConfiguration.class
})
public class IdentityStateMachineAutoConfiguration {

    public IdentityStateMachineAutoConfiguration() {
        // @Import된 Configuration들이 자동 등록됨
        // Action, Guard, Service 등을 @Bean으로 등록
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
}
