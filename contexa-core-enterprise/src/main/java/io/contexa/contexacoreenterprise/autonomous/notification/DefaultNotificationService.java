package io.contexa.contexacoreenterprise.autonomous.notification;

import io.contexa.contexacore.autonomous.notification.NotificationService;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@Slf4j
public class DefaultNotificationService implements NotificationService {

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
        log.warn("[HIGH PRIORITY] {}: {}", type, message);
        
    }

    private void handleMediumPriorityNotification(String type, String message, Map<String, Object> data) {
                
    }

    private void handleLowPriorityNotification(String type, String message, Map<String, Object> data) {
                
    }
}