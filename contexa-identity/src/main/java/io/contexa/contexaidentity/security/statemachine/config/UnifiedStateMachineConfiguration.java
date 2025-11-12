package io.contexa.contexaidentity.security.statemachine.config;

import io.contexa.contexacore.infra.redis.UnifiedRedisConfiguration;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.statemachine.config.kyro.MfaKryoStateMachineSerialisationService;
import io.contexa.contexaidentity.security.statemachine.core.event.MfaEventPublisher;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.listener.MfaStateChangeListener;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.*;
import org.springframework.statemachine.data.redis.RedisPersistingStateMachineInterceptor;
import org.springframework.statemachine.data.redis.RedisRepositoryStateMachinePersist;
import org.springframework.statemachine.data.redis.RedisStateMachineRepository;
import org.springframework.statemachine.persist.DefaultStateMachinePersister;
import org.springframework.statemachine.persist.StateMachinePersister;

/**
 * 통합 State Machine 설정 - Factory 기반 패턴
 *
 * P0 변경 사항:
 * - CommonsPool2TargetSource 제거 (Pool 블로킹 문제 해결)
 * - ProxyFactoryBean 제거 (복잡성 제거)
 * - Request Scope 제거 (Factory 기반 명시적 관리)
 * - StateMachineFactory 직접 사용 (공식 권장 패턴)
 *
 * 보존 사항:
 * - Redis 영속화 (stateMachinePersist, stateMachineRuntimePersister)
 * - 이벤트 발행 (mfaEventPublisher)
 * - 메트릭 수집 (mfaStateChangeListener)
 */
@Slf4j
@Configuration
@Import({UnifiedRedisConfiguration.class, AsyncEventConfiguration.class})
@EnableConfigurationProperties({StateMachineProperties.class, AuthContextProperties.class})
@RequiredArgsConstructor
public class UnifiedStateMachineConfiguration {

    private final StateMachineProperties properties;
    private final AuthContextProperties authContextProperties;

    @Bean
    @SuppressWarnings({"rawtypes"})
    public RedisRepositoryStateMachinePersist<MfaState, MfaEvent> stateMachinePersist(RedisStateMachineRepository redisStateMachineRepository) {
       MfaKryoStateMachineSerialisationService kryoStateMachineSerialisationService =
               new MfaKryoStateMachineSerialisationService();
        return new RedisRepositoryStateMachinePersist(redisStateMachineRepository, kryoStateMachineSerialisationService);
    }


    @Bean
    @SuppressWarnings({"rawtypes"})
    public StateMachinePersister<MfaState, MfaEvent,String> stateMachineRuntimePersister(
            RedisRepositoryStateMachinePersist<MfaState, MfaEvent> stateMachinePersist) {
        RedisPersistingStateMachineInterceptor<MfaState, MfaEvent, Object> stateMachineInterceptor
                = new RedisPersistingStateMachineInterceptor<>(stateMachinePersist);
        return new DefaultStateMachinePersister(stateMachineInterceptor);
    }


    /**
     * MFA 이벤트 발행자
     */
    @Bean
    public MfaEventPublisher mfaEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        log.info("Creating MFA Event Publisher");
        return new MfaEventPublisher(applicationEventPublisher);
    }


    /**
     * State Change Listener (메트릭 수집용)
     */
    @Bean
    @ConditionalOnProperty(prefix = "spring.auth.mfa", name = "metrics-enabled", havingValue = "true", matchIfMissing = true)
    public MfaStateChangeListener mfaStateChangeListener() {
        log.info("Enabling MFA State Change Listener for metrics");
        return new MfaStateChangeListener();
    }
}