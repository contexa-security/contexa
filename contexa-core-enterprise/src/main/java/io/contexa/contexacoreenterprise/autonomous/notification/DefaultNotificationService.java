package io.contexa.contexacoreenterprise.autonomous.notification;

import io.contexa.contexacore.autonomous.notification.NotificationService;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyApprovalService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;

import java.util.HashMap;
import java.util.Map;

@Slf4j
public class DefaultNotificationService implements NotificationService {

    @EventListener
    @Async
    public void onApprovalNotification(PolicyApprovalService.NotificationEvent event) {
        Map<String, Object> data = new HashMap<>();
        data.put("requestId", event.getRequestId());
        data.put("proposalId", event.getProposalId());
        data.put("recipientId", event.getRecipientId());
        data.put("recipientEmail", event.getRecipientEmail());

        sendNotification(
            event.getType().name(),
            event.getMessage(),
            data,
            Priority.HIGH
        );
    }

    @Override
    public void sendNotification(String type, String message, Map<String, Object> data, Priority priority) {

        switch (priority) {
            case CRITICAL:
                handleCriticalNotification(type, message, data);
                break;
            case HIGH:
                handleHighPriorityNotification(type, message, data);
                break;
            case MEDIUM:
                handleMediumPriorityNotification(type, message, data);
                break;
            case LOW:
                handleLowPriorityNotification(type, message, data);
                break;
        }
    }

    private void handleCriticalNotification(String type, String message, Map<String, Object> data) {
        log.error("[CRITICAL ALERT] {}: {}", type, message);
        
    }

    private void handleHighPriorityNotification(String type, String message, Map<String, Object> data) {
        log.error("[HIGH PRIORITY] {}: {}", type, message);
        
    }

    private void handleMediumPriorityNotification(String type, String message, Map<String, Object> data) {
                
    }

    private void handleLowPriorityNotification(String type, String message, Map<String, Object> data) {
                
    }
}