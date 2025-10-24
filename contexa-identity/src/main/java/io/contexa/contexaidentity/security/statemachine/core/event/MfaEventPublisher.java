package io.contexa.contexaidentity.security.statemachine.core.event;

import io.contexa.contexaidentity.security.statemachine.core.event.MfaStateMachineEvents.*;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * MFA 이벤트 발행자
 * Spring의 ApplicationEventPublisher를 사용한 이벤트 발행
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MfaEventPublisher {

    private final ApplicationEventPublisher eventPublisher;

    /**
     * 상태 변경 이벤트 발행
     */
    public void publishStateChange(String sessionId, MfaState fromState,
                                   MfaState toState, MfaEvent event) {
        publishStateChange(sessionId, fromState, toState, event, null);
    }

    /**
     * 상태 변경 이벤트 발행 (Duration 포함)
     */
    public void publishStateChange(String sessionId, MfaState fromState,
                                   MfaState toState, MfaEvent event,
                                   Duration duration) {
        try {
            StateChangeEvent stateChangeEvent = new StateChangeEvent(
                    this, sessionId, fromState, toState, event, duration
            );

            eventPublisher.publishEvent(stateChangeEvent);

            log.debug("Published state change event: {} -> {} for session: {}",
                    fromState, toState, sessionId);

        } catch (Exception e) {
            log.error("Failed to publish state change event", e);
        }
    }

    /**
     * 에러 이벤트 발행
     */
    public void publishError(String sessionId, MfaState currentState,
                             MfaEvent event, Exception error) {
        try {
            ErrorEvent errorEvent = new ErrorEvent(
                    this, sessionId, currentState, event, error
            );

            eventPublisher.publishEvent(errorEvent);

            log.debug("Published error event for session: {}", sessionId);

        } catch (Exception e) {
            log.error("Failed to publish error event", e);
        }
    }

    /**
     * 커스텀 이벤트 발행
     */
    public void publishCustomEvent(String eventType, Object payload) {
        try {
            CustomEvent customEvent = new CustomEvent(
                    this, eventType, payload
            );

            eventPublisher.publishEvent(customEvent);

            log.debug("Published custom event: {}", eventType);

        } catch (Exception e) {
            log.error("Failed to publish custom event", e);
        }
    }
}