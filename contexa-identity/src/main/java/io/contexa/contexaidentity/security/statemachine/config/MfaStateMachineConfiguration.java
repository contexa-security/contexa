package io.contexa.contexaidentity.security.statemachine.config;

import io.contexa.contexaidentity.security.statemachine.action.*;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.guard.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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

    private final InitializeMfaAction initializeMfaAction;
    private final SelectFactorAction selectFactorAction;
    private final InitiateChallengeAction initiateChallengeAction;
    private final VerifyFactorAction verifyFactorAction;
    private final CompleteMfaAction completeMfaAction;
    private final HandleFailureAction handleFailureAction;
    private final DetermineNextFactorAction determineNextFactorAction;

    private final AllFactorsCompletedGuard allFactorsCompletedGuard;
    private final RetryLimitGuard retryLimitGuard;

    @Override
    public void configure(StateMachineConfigurationConfigurer<MfaState, MfaEvent> config) throws Exception {

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

                .withExternal()
                .source(MfaState.NONE)
                .target(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .event(MfaEvent.PRIMARY_AUTH_SUCCESS)
                .action(initializeMfaAction)
                .and()

                .withExternal()
                .source(MfaState.NONE)
                .target(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .event(MfaEvent.ADAPTIVE_MFA_REQUIRED)
                .action(initializeMfaAction)
                .and()

                .withExternal()
                .source(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .target(MfaState.MFA_NOT_REQUIRED)
                .event(MfaEvent.MFA_NOT_REQUIRED)
                .and()

                .withExternal()
                .source(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.MFA_REQUIRED_SELECT_FACTOR)
                .and()

                .withExternal()
                .source(MfaState.AWAITING_FACTOR_SELECTION)
                .target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .event(MfaEvent.FACTOR_SELECTED)
                .action(selectFactorAction)
                .and()

                .withExternal()
                .source(MfaState.PRIMARY_AUTHENTICATION_COMPLETED)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.INITIATE_CHALLENGE_AUTO)
                .action(initiateChallengeAction)
                .and()

                .withExternal()
                .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.INITIATE_CHALLENGE)
                .action(initiateChallengeAction)
                .and()

                .withInternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.INITIATE_CHALLENGE)
                .action(initiateChallengeAction)
                .and()

                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .target(MfaState.FACTOR_VERIFICATION_PENDING)
                .event(MfaEvent.SUBMIT_FACTOR_CREDENTIAL)
                .and()

                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_PENDING)
                .target(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .event(MfaEvent.FACTOR_VERIFIED_SUCCESS)
                .action(verifyFactorAction)
                .and()

                .withInternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .event(MfaEvent.DETERMINE_NEXT_FACTOR)
                .action(determineNextFactorAction)
                .and()

                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_PENDING)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.FACTOR_VERIFICATION_FAILED)
                .guard(retryLimitGuard)
                .action(handleFailureAction)
                .and()

                // Fallback transition: retry limit exceeded -> terminal state
                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_PENDING)
                .target(MfaState.MFA_RETRY_LIMIT_EXCEEDED)
                .event(MfaEvent.FACTOR_VERIFICATION_FAILED)
                .guard(retryLimitGuard.negate())
                .action(handleFailureAction)
                .and()

                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_PENDING)
                .target(MfaState.MFA_RETRY_LIMIT_EXCEEDED)
                .event(MfaEvent.RETRY_LIMIT_EXCEEDED)
                .and()

                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.ALL_FACTORS_COMPLETED)
                .event(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED)
                .guard(allFactorsCompletedGuard)
                .and()

                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED)
                .guard(allFactorsCompletedGuard.negate())
                .and()

                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.MFA_REQUIRED_SELECT_FACTOR)
                .and()

                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .event(MfaEvent.FACTOR_SELECTED)
                .action(selectFactorAction)
                .and()

                .withExternal()
                .source(MfaState.FACTOR_VERIFICATION_COMPLETED)
                .target(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .event(MfaEvent.INITIATE_CHALLENGE_AUTO)
                .action(initiateChallengeAction)
                .and()

                .withExternal()
                .source(MfaState.ALL_FACTORS_COMPLETED)
                .target(MfaState.MFA_SUCCESSFUL)
                .event(MfaEvent.ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN)
                .action(completeMfaAction)
                .and()

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

                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.CHALLENGE_TIMEOUT)
                .and()

                // Allow user to switch to a different factor from challenge or initiation states
                .withExternal()
                .source(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.MFA_REQUIRED_SELECT_FACTOR)
                .and()
                .withExternal()
                .source(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION)
                .target(MfaState.AWAITING_FACTOR_SELECTION)
                .event(MfaEvent.MFA_REQUIRED_SELECT_FACTOR)
                .and()

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
                } else {
                }
            }

            @Override
            public void stateMachineError(org.springframework.statemachine.StateMachine<MfaState, MfaEvent> stateMachine,
                                          Exception exception) {
                String machineId = stateMachine.getId();
                MfaState currentState = stateMachine.getState() != null ?
                        stateMachine.getState().getId() : null;

                log.error("[MFA SM] [{}] StateMachine error occurred (current state: {}): {}",
                        machineId, currentState, exception.getMessage(), exception);
            }

            @Override
            public void eventNotAccepted(org.springframework.messaging.Message<MfaEvent> event) {
                MfaEvent mfaEvent = event.getPayload();
                Object sessionId = event.getHeaders().get("sessionId");

                log.error("[MFA SM] [{}] Event rejected: {} (headers: {})",
                        sessionId, mfaEvent, event.getHeaders());
            }

            @Override
            public void stateMachineStopped(org.springframework.statemachine.StateMachine<MfaState, MfaEvent> stateMachine) {
                String machineId = stateMachine.getId();
            }
        };
    }
}