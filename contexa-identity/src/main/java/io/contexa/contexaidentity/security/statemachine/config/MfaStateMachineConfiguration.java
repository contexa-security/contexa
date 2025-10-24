package io.contexa.contexaidentity.security.statemachine.config;

import io.contexa.contexaidentity.security.statemachine.action.*;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.guard.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.statemachine.config.EnableStateMachineFactory;
import org.springframework.statemachine.config.EnumStateMachineConfigurerAdapter;
import org.springframework.statemachine.config.builders.StateMachineConfigurationConfigurer;
import org.springframework.statemachine.config.builders.StateMachineStateConfigurer;
import org.springframework.statemachine.config.builders.StateMachineTransitionConfigurer;
import org.springframework.statemachine.listener.StateMachineListener;
import org.springframework.statemachine.listener.StateMachineListenerAdapter;
import org.springframework.statemachine.persist.StateMachineRuntimePersister;
import org.springframework.statemachine.state.State;

import java.util.EnumSet;

@Slf4j
@Configuration
@EnableStateMachineFactory
@RequiredArgsConstructor
public class MfaStateMachineConfiguration extends EnumStateMachineConfigurerAdapter<MfaState, MfaEvent> {

    // Actions
    private final InitializeMfaAction initializeMfaAction;
    private final SelectFactorAction selectFactorAction;
    private final InitiateChallengeAction initiateChallengeAction;
    private final VerifyFactorAction verifyFactorAction;
    private final CompleteMfaAction completeMfaAction;
    private final HandleFailureAction handleFailureAction;
    private StateMachineRuntimePersister<MfaState, MfaEvent, String> stateMachinePersister;

    // Guards
    private final AllFactorsCompletedGuard allFactorsCompletedGuard;
    private final RetryLimitGuard retryLimitGuard;

    @Override
    public void configure(StateMachineConfigurationConfigurer<MfaState, MfaEvent> config) throws Exception {
//        config
//                .withPersistence()
//                .runtimePersister(stateMachinePersister);
        config
                .withConfiguration()
                .autoStartup(false)
                .machineId("mfaStateMachine")
                .listener(listener());
    }

    @Override
    public void configure(StateMachineStateConfigurer<MfaState, MfaEvent> states) throws Exception {
        states
                .withStates()
                .initial(MfaState.NONE)
                .states(EnumSet.allOf(MfaState.class))
                .end(MfaState.MFA_SUCCESSFUL)
                .end(MfaState.MFA_FAILED_TERMINAL)
                .end(MfaState.MFA_CANCELLED)
                .end(MfaState.MFA_SESSION_EXPIRED)
                .end(MfaState.MFA_NOT_REQUIRED)
                .end(MfaState.MFA_SYSTEM_ERROR)
                .end(MfaState.MFA_SESSION_INVALIDATED);
    }

    @Override
    public void configure(StateMachineTransitionConfigurer<MfaState, MfaEvent> transitions) throws Exception {
        transitions
                // 초기 전이 - PRIMARY_AUTHENTICATION_COMPLETED로 직접 이동
                .withExternal()
                .source(MfaState.NONE)
                .target(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .event(MfaEvent.PRIMARY_AUTH_SUCCESS)
                .action(initializeMfaAction)
                .and()

                // MFA 정책 평가 결과 - MFA 불필요
                .withExternal()
                .source(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .target(MfaState.MFA_NOT_REQUIRED)
                .event(MfaEvent.MFA_NOT_REQUIRED)
                .and()

                // MFA 정책 평가 결과 - MFA 필요
                .withExternal()
                .source(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.MFA_REQUIRED_SELECT_FACTOR)
                .and()

                // MFA 구성 필요
                .withExternal()
                .source(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .target(MfaState.MFA_CONFIGURATION_REQUIRED)
                .event(MfaEvent.MFA_CONFIGURATION_REQUIRED)
                .and()

                // 팩터 선택 후 챌린지 준비 상태로
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_SELECTION)
                .target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .event(MfaEvent.FACTOR_SELECTED)
                .action(selectFactorAction)
                .and()

                // 자동 선택 경로 (PRIMARY_AUTHENTICATION_COMPLETED → 바로 챌린지)
                .withExternal()
                .source(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.INITIATE_CHALLENGE_AUTO)
                .action(initiateChallengeAction)
                .and()

                // 일반 경로 (팩터 선택 후 → 챌린지)
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.INITIATE_CHALLENGE)
                .action(initiateChallengeAction)
                .and()

                /*  // 챌린지 성공적 시작 -> 사용자 입력 대기
                  .withExternal()
                  .source(MfaState.FACTOR_CHALLENGE_INITIATED)
                  .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                  .event(MfaEvent.CHALLENGE_INITIATED_SUCCESSFULLY)
                  .and()

                  // 챌린지 시작 실패 -> 팩터 선택으로 돌아감
                  .withExternal()
                  .source(MfaState.FACTOR_CHALLENGE_INITIATED)
                  .target(MfaState.AWAITING_FACTOR_SELECTION)
                  .event(MfaEvent.CHALLENGE_INITIATION_FAILED)
                  .and()*/

                // 검증 시도
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .target(MfaState.FACTOR_VERIFICATION_PENDING)
                .event(MfaEvent.SUBMIT_FACTOR_CREDENTIAL)
                .and()

                // 검증 성공
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_PENDING)
                .target(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .event(MfaEvent.FACTOR_VERIFIED_SUCCESS)
                .action(verifyFactorAction)
                .and()

                // 검증 실패 (재시도 가능)
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_PENDING)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.FACTOR_VERIFICATION_FAILED)
                .guard(retryLimitGuard)
                .action(handleFailureAction)
                .and()

                // 재시도 한계 초과
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_PENDING)
                .target(MfaState.MFA_RETRY_LIMIT_EXCEEDED)
                .event(MfaEvent.RETRY_LIMIT_EXCEEDED)
                .and()

                // 모든 팩터 완료 확인 - 성공
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.ALL_FACTORS_COMPLETED)
                .event(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED)
                .guard(allFactorsCompletedGuard)
                .and()

                // 추가 팩터 필요
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED)
                .guard(allFactorsCompletedGuard.negate())
                .and()

                // 최종 성공
                .withExternal()
                .source(MfaState.ALL_FACTORS_COMPLETED)
                .target(MfaState.MFA_SUCCESSFUL)
                .event(MfaEvent.ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN)
                .action(completeMfaAction)
                .and()

                // 사용자 취소 (다양한 상태에서)
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_SELECTION)
                .target(MfaState.MFA_CANCELLED)
                .event(MfaEvent.USER_ABORTED_MFA)
                .and()
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .target(MfaState.MFA_CANCELLED)
                .event(MfaEvent.USER_ABORTED_MFA)
                .and()
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .target(MfaState.MFA_CANCELLED)
                .event(MfaEvent.USER_ABORTED_MFA)
                .and()

                // 세션 타임아웃 (다양한 상태에서)
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_SELECTION)
                .target(MfaState.MFA_SESSION_EXPIRED)
                .event(MfaEvent.SESSION_TIMEOUT)
                .and()
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .target(MfaState.MFA_SESSION_EXPIRED)
                .event(MfaEvent.SESSION_TIMEOUT)
                .and()
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .target(MfaState.MFA_SESSION_EXPIRED)
                .event(MfaEvent.SESSION_TIMEOUT)
                .and()

                // 챌린지 타임아웃
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.CHALLENGE_TIMEOUT)
                .and()

                // 시스템 에러 처리 (다양한 상태에서)
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_PENDING)
                .target(MfaState.MFA_SYSTEM_ERROR)
                .event(MfaEvent.SYSTEM_ERROR)
                .and()
                .withExternal()
                .source(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .target(MfaState.MFA_SYSTEM_ERROR)
                .event(MfaEvent.SYSTEM_ERROR)
                .and()
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_SELECTION)
                .target(MfaState.MFA_SYSTEM_ERROR)
                .event(MfaEvent.SYSTEM_ERROR)
                .and()
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_INITIATED)
                .target(MfaState.MFA_SYSTEM_ERROR)
                .event(MfaEvent.SYSTEM_ERROR)
                .and()
                .withExternal()
                .source(MfaState.MFA_SUCCESSFUL)
                .target(MfaState.MFA_SYSTEM_ERROR)
                .event(MfaEvent.SYSTEM_ERROR)
                .and()

                // 재시도 한계 초과에서 실패로
                .withExternal()
                .source(MfaState.MFA_RETRY_LIMIT_EXCEEDED)
                .target(MfaState.MFA_FAILED_TERMINAL)
                .event(MfaEvent.SYSTEM_ERROR);
    }

    @Bean
    public StateMachineListener<MfaState, MfaEvent> listener() {
        return new StateMachineListenerAdapter<MfaState, MfaEvent>() {
            @Override
            public void stateChanged(State<MfaState, MfaEvent> from, State<MfaState, MfaEvent> to) {
                if (from != null) {
                    log.info("State changed from {} to {}", from.getId(), to.getId());
                } else {
                    log.info("State machine started with state: {}", to.getId());
                }
            }
        };
    }
}