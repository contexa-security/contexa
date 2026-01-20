package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.autonomous.domain.NotificationResult;

import java.util.Map;
import java.util.concurrent.CompletableFuture;


public interface ISoarNotifier {
    
    
    CompletableFuture<NotificationResult> notifyIncident(SecurityIncident incident, SoarContext context);
    
    
    CompletableFuture<NotificationResult> notifyCriticalSituation(SoarContext context);
    
    
    CompletableFuture<NotificationResult> notifyHighRiskTool(String toolName, Map<String, Object> toolParameters, SoarContext context);
    
    
    Map<String, Object> getNotificationStatistics();

    
    default NotificationResult notifyCriticalEvent(Object event, Map<String, Object> data) {
        
        return NotificationResult.success("default-notification", "Default notification");
    }

    
    default NotificationResult notifyWarningEvent(Object event, Map<String, Object> data) {
        
        return NotificationResult.success("default-notification", "Default notification");
    }

    
    default NotificationResult notifyApprovalRequired(Object event, Map<String, Object> data) {
        
        return NotificationResult.success("default-notification", "Default notification");
    }

    
    default NotificationResult notifyEscalation(Object event, Map<String, Object> data) {
        
        return NotificationResult.success("default-notification", "Default notification");
    }
    
    
    boolean isSoarAvailable();
    
}