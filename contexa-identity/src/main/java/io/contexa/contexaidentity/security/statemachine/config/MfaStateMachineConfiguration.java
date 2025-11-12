package io.contexa.contexaidentity.security.statemachine.config;

import io.contexa.contexaidentity.security.statemachine.action.*;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.guard.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.statemachine.action.StateDoActionPolicy;
import org.springframework.statemachine.config.EnableStateMachineFactory;
import org.springframework.statemachine.config.EnumStateMachineConfigurerAdapter;
import org.springframework.statemachine.config.builders.StateMachineConfigurationConfigurer;
import org.springframework.statemachine.config.builders.StateMachineStateConfigurer;
import org.springframework.statemachine.config.builders.StateMachineTransitionConfigurer;
import org.springframework.statemachine.listener.StateMachineListener;
import org.springframework.statemachine.listener.StateMachineListenerAdapter;
import org.springframework.statemachine.state.State;
import org.springframework.statemachine.transition.TransitionConflictPolicy;

import java.util.EnumSet;

@Slf4j
@Configuration
@EnableStateMachineFactory
@RequiredArgsConstructor
public class MfaStateMachineConfiguration extends EnumStateMachineConfigurerAdapter<MfaState, MfaEvent> {

    // P1: StateMachineProperties 주입
    private final StateMachineProperties properties;

    // Actions
    private final InitializeMfaAction initializeMfaAction;
    private final SelectFactorAction selectFactorAction;
    private final InitiateChallengeAction initiateChallengeAction;
    private final VerifyFactorAction verifyFactorAction;
    private final CompleteMfaAction completeMfaAction;
    private final HandleFailureAction handleFailureAction;
    private final DetermineNextFactorAction determineNextFactorAction;

    // Guards
    private final AllFactorsCompletedGuard allFactorsCompletedGuard;
    private final RetryLimitGuard retryLimitGuard;

    /**
     * P1: StateMachine 설정 개선
     *
     * Factory 기반 패턴:
     * - autoStartup(false): Factory에서 명시적 start() 제어
     * - machineId 제거: sessionId 기반 동적 ID 사용
     *
     * P1 Properties 활용:
     * - MFA 관련 설정 로깅 (최대 재시도, 세션 타임아웃, 전이 타임아웃)
     *
     * P1 Policy 설정:
     * - StateDoActionPolicy.TIMEOUT_CANCEL: Action 실행 타임아웃 시 취소
     * - TransitionConflictPolicy.PARENT: 전이 충돌 시 부모 우선
     */
    @Override
    public void configure(StateMachineConfigurationConfigurer<MfaState, MfaEvent> config) throws Exception {
        // P1: Properties 로깅 (Guard 및 Handler에서 활용)
        log.info("===================================================");
        log.info("MFA StateMachine Configuration (Properties-based)");
        log.info("  - MFA 최대 재시도: {}", properties.getMfa().getMaxRetries());
        log.info("  - MFA 세션 타임아웃: {}분", properties.getMfa().getSessionTimeoutMinutes());
        log.info("  - MFA 전이 타임아웃: {}초", properties.getMfa().getTransitionTimeoutSeconds());
        log.info("  - MFA 동시 세션 제한: {}", properties.getMfa().getMaxConcurrentSessions());
        log.info("  - MFA 메트릭 수집: {}", properties.getMfa().isEnableMetrics());
        log.info("  - StateDoActionPolicy: TIMEOUT_CANCEL");
        log.info("  - TransitionConflictPolicy: PARENT");
        log.info("===================================================");

        config
                .withConfiguration()
                .autoStartup(false)
                .stateDoActionPolicy(StateDoActionPolicy.TIMEOUT_CANCEL)
                .transitionConflictPolicy(TransitionConflictPolicy.PARENT)
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

                // Phase 6: 챌린지 만료 후 재시작 허용 (내부 전이 - 상태 변경 없이 액션만 실행)
                .withInternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.INITIATE_CHALLENGE)
                .action(initiateChallengeAction)
                .and()

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

                // Phase 2: 내부 전이 - 다음 팩터 결정 (상태 변경 없이 Action만 실행)
                .withInternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .event(MfaEvent.DETERMINE_NEXT_FACTOR)
                .action(determineNextFactorAction)
                .and()

                // Phase 3: CHECK_COMPLETION 전이 제거됨 (Handler에서 직접 평가)

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
//                .guard(allFactorsCompletedGuard)
                .and()

                // 추가 팩터 필요
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED)
                .guard(allFactorsCompletedGuard.negate())
                .and()

                // Phase 2: 팩터 선택 필요 시 전송 (수동 선택)
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.MFA_REQUIRED_SELECT_FACTOR)
                .and()

                // Phase 2: 다음 팩터 자동 선택됨
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .event(MfaEvent.FACTOR_SELECTED)
                .action(selectFactorAction)
                .and()

                // Phase 2.3: Option 2 - 다음 팩터 자동 선택 후 바로 챌린지 (2차 → 3차 전이)
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.INITIATE_CHALLENGE_AUTO)
                .action(initiateChallengeAction)
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
                .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
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

    /**
     * P1: Error Handling Listener
     *
     * StateMachine 실행 중 발생하는 오류를 감지하고 로깅합니다:
     * - stateChanged: 상태 전이 로깅
     * - stateMachineError: 오류 발생 시 상세 로깅
     * - eventNotAccepted: 이벤트 거부 시 로깅
     * - stateMachineStopped: 인스턴스 종료 로깅
     */
    @Bean
    public StateMachineListener<MfaState, MfaEvent> listener() {
        return new StateMachineListenerAdapter<MfaState, MfaEvent>() {
            @Override
            public void stateChanged(State<MfaState, MfaEvent> from, State<MfaState, MfaEvent> to) {
                if (from != null) {
                    log.info("[MFA SM] State changed: {} → {}", from.getId(), to.getId());
                } else {
                    log.info("[MFA SM] State machine started with state: {}", to.getId());
                }
            }

            @Override
            public void stateMachineError(org.springframework.statemachine.StateMachine<MfaState, MfaEvent> stateMachine,
                                          Exception exception) {
                String machineId = stateMachine.getId();
                MfaState currentState = stateMachine.getState() != null ?
                    stateMachine.getState().getId() : null;

                log.error("[MFA SM] [{}] StateMachine 오류 발생 (현재 상태: {}): {}",
                    machineId, currentState, exception.getMessage(), exception);
            }

            @Override
            public void eventNotAccepted(org.springframework.messaging.Message<MfaEvent> event) {
                MfaEvent mfaEvent = event.getPayload();
                Object sessionId = event.getHeaders().get("sessionId");

                log.warn("[MFA SM] [{}] 이벤트 거부됨: {} (헤더: {})",
                    sessionId, mfaEvent, event.getHeaders());
            }

            @Override
            public void stateMachineStopped(org.springframework.statemachine.StateMachine<MfaState, MfaEvent> stateMachine) {
                String machineId = stateMachine.getId();
                log.debug("[MFA SM] [{}] StateMachine 종료됨", machineId);
            }
        };
    }
}