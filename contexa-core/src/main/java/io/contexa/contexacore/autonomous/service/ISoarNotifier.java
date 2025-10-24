package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.autonomous.domain.NotificationResult;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * SOAR Notifier Interface
 * 
 * Notifies SOAR system about security situations.
 * SOAR will then request appropriate tools from AI.
 */
public interface ISoarNotifier {
    
    /**
     * Notify SOAR about security incident
     * 
     * @param incident Security incident
     * @param context SOAR context with situation details
     * @return Future with notification result
     */
    CompletableFuture<NotificationResult> notifyIncident(SecurityIncident incident, SoarContext context);
    
    /**
     * Notify SOAR about critical situation
     * 
     * @param context SOAR context with critical situation details
     * @return Future with notification result
     */
    CompletableFuture<NotificationResult> notifyCriticalSituation(SoarContext context);
    
    /**
     * Notify SOAR about high-risk tool execution
     * 
     * @param toolName Tool name
     * @param toolParameters Tool parameters
     * @param context SOAR context
     * @return Future with notification result
     */
    CompletableFuture<NotificationResult> notifyHighRiskTool(String toolName, Map<String, Object> toolParameters, SoarContext context);
    
    /**
     * Get notification statistics
     *
     * @return Notification statistics map
     */
    Map<String, Object> getNotificationStatistics();

    /**
     * Notify about critical event
     *
     * @param event Security event
     * @param data Notification data
     * @return Notification result
     */
    default NotificationResult notifyCriticalEvent(Object event, Map<String, Object> data) {
        // Default implementation for backward compatibility
        return NotificationResult.success("default-notification", "Default notification");
    }

    /**
     * Notify about warning event
     *
     * @param event Security event
     * @param data Notification data
     * @return Notification result
     */
    default NotificationResult notifyWarningEvent(Object event, Map<String, Object> data) {
        // Default implementation for backward compatibility
        return NotificationResult.success("default-notification", "Default notification");
    }

    /**
     * Notify about approval required
     *
     * @param event Security event
     * @param data Notification data
     * @return Notification result
     */
    default NotificationResult notifyApprovalRequired(Object event, Map<String, Object> data) {
        // Default implementation for backward compatibility
        return NotificationResult.success("default-notification", "Default notification");
    }

    /**
     * Notify about escalation
     *
     * @param event Security event
     * @param data Notification data
     * @return Notification result
     */
    default NotificationResult notifyEscalation(Object event, Map<String, Object> data) {
        // Default implementation for backward compatibility
        return NotificationResult.success("default-notification", "Default notification");
    }
    
    /**
     * Check if SOAR system is available
     * 
     * @return true if SOAR is available
     */
    boolean isSoarAvailable();
    
}