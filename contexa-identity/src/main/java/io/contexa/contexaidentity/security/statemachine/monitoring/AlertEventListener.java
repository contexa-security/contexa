package io.contexa.contexaidentity.security.statemachine.monitoring;

import io.contexa.contexaidentity.security.statemachine.core.event.MfaStateMachineEvents;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * 성능 알림 처리 리스너
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AlertEventListener {

    @EventListener
    @Async("mfaEventExecutor")
    public void handlePerformanceAlert(MfaStateMachineEvents.PerformanceAlertEvent event) {
        log.warn("Performance Alert: {} - {} (threshold: {}, actual: {})",
                event.getSeverity(),
                event.getDescription(),
                event.getThreshold(),
                event.getActualValue());

        // 심각도에 따른 처리
        switch (event.getSeverity()) {
            case CRITICAL:
                sendImmediateAlert(event);
                break;
            case HIGH:
                scheduleAlert(event);
                break;
            default:
                logAlert(event);
        }
    }

    private void sendImmediateAlert(MfaStateMachineEvents.PerformanceAlertEvent event) {
        // Slack, Email, PagerDuty 등 즉시 알림
        log.error("CRITICAL ALERT: {}", event.getDescription());
    }

    private void scheduleAlert(MfaStateMachineEvents.PerformanceAlertEvent event) {
        // 배치 알림으로 스케줄링
        log.warn("HIGH ALERT scheduled: {}", event.getDescription());
    }

    private void logAlert(MfaStateMachineEvents.PerformanceAlertEvent event) {
        // 로그만 기록
        log.info("Alert logged: {}", event.getDescription());
    }
}