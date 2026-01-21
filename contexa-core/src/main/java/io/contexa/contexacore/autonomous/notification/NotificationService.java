package io.contexa.contexacore.autonomous.notification;

import java.util.Map;

public interface NotificationService {

    enum Priority {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    void sendNotification(String type, String message, Map<String, Object> data, Priority priority);

    default void sendNotificationAsync(String type, String message, Map<String, Object> data, Priority priority) {
        
        sendNotification(type, message, data, priority);
    }
}
