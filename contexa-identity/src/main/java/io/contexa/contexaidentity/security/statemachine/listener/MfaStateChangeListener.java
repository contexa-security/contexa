package io.contexa.contexaidentity.security.statemachine.listener;

import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.listener.StateMachineListenerAdapter;
import org.springframework.statemachine.state.State;
import org.springframework.statemachine.transition.Transition;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@Component
public class MfaStateChangeListener extends StateMachineListenerAdapter<MfaState, MfaEvent>
        implements MfaStateMachineListener {

    private final ConcurrentHashMap<String, AtomicLong> stateChangeCounters = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> eventCounters = new ConcurrentHashMap<>();

    @Override
    public void stateChanged(State<MfaState, MfaEvent> from, State<MfaState, MfaEvent> to) {
        String fromState = from != null ? from.getId().name() : "INITIAL";
        String toState = to.getId().name();

        recordStateChange(fromState, toState);
    }

    @Override
    public void transition(Transition<MfaState, MfaEvent> transition) {
        if (transition.getTrigger() != null && transition.getTrigger().getEvent() != null) {
            MfaEvent event = transition.getTrigger().getEvent();

            eventCounters.computeIfAbsent(event.name(), k -> new AtomicLong(0)).incrementAndGet();
        }
    }

    @Override
    public void stateMachineError(org.springframework.statemachine.StateMachine<MfaState, MfaEvent> stateMachine,
                                  Exception exception) {
        log.error("State machine error occurred: {}", exception.getMessage(), exception);
        handleStateMachineError(stateMachine.getId(), exception);
    }

    @Override
    public void onSuccessfulTransition(String sessionId, MfaState fromState, MfaState toState, MfaEvent event) {

        if (toState == MfaState.MFA_SUCCESSFUL) {
                        
        }
    }

    @Override
    public void onFailedTransition(String sessionId, MfaState currentState, MfaEvent event, Exception error) {
        log.error("Failed MFA transition for session {}: current state {}, event {}, error: {}",
                sessionId, currentState, event, error.getMessage());

        if (currentState == MfaState.MFA_RETRY_LIMIT_EXCEEDED) {
            log.warn("MFA retry limit exceeded for session: {}", sessionId);
            
        }
    }

    private void recordStateChange(String fromState, String toState) {
        String transitionKey = fromState + "_TO_" + toState;
        stateChangeCounters.computeIfAbsent(transitionKey, k -> new AtomicLong(0)).incrementAndGet();

            }

    private void handleStateMachineError(String machineId, Exception exception) {

        log.error("Handling state machine error for machine {}: {}",
                machineId, exception.getClass().getSimpleName());
    }

    public long getStateChangeCount(String fromState, String toState) {
        String key = fromState + "_TO_" + toState;
        AtomicLong counter = stateChangeCounters.get(key);
        return counter != null ? counter.get() : 0;
    }

    public long getEventCount(String event) {
        AtomicLong counter = eventCounters.get(event);
        return counter != null ? counter.get() : 0;
    }
}