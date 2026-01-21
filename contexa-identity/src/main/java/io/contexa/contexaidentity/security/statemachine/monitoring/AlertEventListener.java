package io.contexa.contexaidentity.security.statemachine.monitoring;

import io.contexa.contexaidentity.security.statemachine.core.event.MfaStateMachineEvents;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

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
        
        log.error("CRITICAL ALERT: {}", event.getDescription());
    }

    private void scheduleAlert(MfaStateMachineEvents.PerformanceAlertEvent event) {
        
        log.warn("HIGH ALERT scheduled: {}", event.getDescription());
    }

    private void logAlert(MfaStateMachineEvents.PerformanceAlertEvent event) {
        
            }
}