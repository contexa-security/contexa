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

/**
 * MFA 상태 변경 리스너
 * 상태 변경 이벤트를 감지하고 메트릭을 수집
 */
@Slf4j
@Component
public class MfaStateChangeListener extends StateMachineListenerAdapter<MfaState, MfaEvent>
        implements MfaStateMachineListener {

    // 메트릭 수집을 위한 카운터
    private final ConcurrentHashMap<String, AtomicLong> stateChangeCounters = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> eventCounters = new ConcurrentHashMap<>();

    @Override
    public void stateChanged(State<MfaState, MfaEvent> from, State<MfaState, MfaEvent> to) {
        String fromState = from != null ? from.getId().name() : "INITIAL";
        String toState = to.getId().name();

        log.info("MFA State changed from {} to {} at {}", fromState, toState, LocalDateTime.now());

        // 상태 변경 기록
        recordStateChange(fromState, toState);
    }

    @Override
    public void transition(Transition<MfaState, MfaEvent> transition) {
        if (transition.getTrigger() != null && transition.getTrigger().getEvent() != null) {
            MfaEvent event = transition.getTrigger().getEvent();
            log.debug("MFA Transition triggered by event: {}", event);

            // 이벤트 카운터 증가
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
        log.info("Successful MFA transition for session {}: {} -> {} via event {}",
                sessionId, fromState, toState, event);

        // 성공적인 전이에 대한 추가 처리
        if (toState == MfaState.MFA_SUCCESSFUL) {
            log.info("MFA completed successfully for session: {}", sessionId);
            // TODO: 성공 메트릭 기록
        }
    }

    @Override
    public void onFailedTransition(String sessionId, MfaState currentState, MfaEvent event, Exception error) {
        log.error("Failed MFA transition for session {}: current state {}, event {}, error: {}",
                sessionId, currentState, event, error.getMessage());

        // 실패한 전이에 대한 추가 처리
        if (currentState == MfaState.MFA_RETRY_LIMIT_EXCEEDED) {
            log.warn("MFA retry limit exceeded for session: {}", sessionId);
            // TODO: 재시도 한계 초과 알림
        }
    }

    /**
     * 상태 변경 기록
     */
    private void recordStateChange(String fromState, String toState) {
        String transitionKey = fromState + "_TO_" + toState;
        stateChangeCounters.computeIfAbsent(transitionKey, k -> new AtomicLong(0)).incrementAndGet();

        // TODO: 실제 메트릭 시스템(예: Micrometer)과 연동
        log.debug("State transition {} recorded. Total count: {}",
                transitionKey, stateChangeCounters.get(transitionKey).get());
    }

    /**
     * 상태 머신 에러 처리
     */
    private void handleStateMachineError(String machineId, Exception exception) {
        // TODO: 에러 알림 시스템과 연동
        // TODO: 복구 가능한 에러인 경우 복구 시도

        log.error("Handling state machine error for machine {}: {}",
                machineId, exception.getClass().getSimpleName());
    }

    /**
     * 메트릭 조회 메서드
     */
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