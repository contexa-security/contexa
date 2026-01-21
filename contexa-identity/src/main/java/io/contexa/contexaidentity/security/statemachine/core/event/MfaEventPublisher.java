package io.contexa.contexaidentity.security.statemachine.core.event;

import io.contexa.contexaidentity.security.statemachine.core.event.MfaStateMachineEvents.*;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Slf4j
@Component
@RequiredArgsConstructor
public class MfaEventPublisher {

    private final ApplicationEventPublisher eventPublisher;

    public void publishStateChange(String sessionId, MfaState fromState,
                                   MfaState toState, MfaEvent event) {
        publishStateChange(sessionId, fromState, toState, event, null);
    }

    public void publishStateChange(String sessionId, MfaState fromState,
                                   MfaState toState, MfaEvent event,
                                   Duration duration) {
        try {
            StateChangeEvent stateChangeEvent = new StateChangeEvent(
                    this, sessionId, fromState, toState, event, duration
            );

            eventPublisher.publishEvent(stateChangeEvent);

        } catch (Exception e) {
            log.error("Failed to publish state change event", e);
        }
    }

    public void publishError(String sessionId, MfaState currentState,
                             MfaEvent event, Exception error) {
        try {
            ErrorEvent errorEvent = new ErrorEvent(
                    this, sessionId, currentState, event, error
            );

            eventPublisher.publishEvent(errorEvent);

        } catch (Exception e) {
            log.error("Failed to publish error event", e);
        }
    }

    public void publishCustomEvent(String eventType, Object payload) {
        try {
            CustomEvent customEvent = new CustomEvent(
                    this, eventType, payload
            );

            eventPublisher.publishEvent(customEvent);

        } catch (Exception e) {
            log.error("Failed to publish custom event", e);
        }
    }
}