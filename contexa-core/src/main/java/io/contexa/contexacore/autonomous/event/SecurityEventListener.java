package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;


public interface SecurityEventListener {

    
    Logger log = LoggerFactory.getLogger(SecurityEventListener.class);

    
    default String getListenerName() {
        return this.getClass().getSimpleName();
    }
    
    
    void onSecurityEvent(SecurityEvent event);
    
    
    default void onBatchEvents(List<SecurityEvent> events) {
        log.debug("[SecurityEventListener] Processing batch events: count={}", events.size());
        for (SecurityEvent event : events) {
            onSecurityEvent(event);
        }
    }
    
    
    default void onBlockEvent(SecurityEvent event, SecurityDecision decision) {
        if (decision != null && decision.getAction() == SecurityDecision.Action.BLOCK) {
            onSecurityEvent(event);
        }
    }

    
    default void onChallengeEvent(SecurityEvent event, SecurityDecision decision) {
        if (decision != null && decision.getAction() == SecurityDecision.Action.CHALLENGE) {
            onSecurityEvent(event);
        }
    }

    
    default void onHighRiskEventByAction(SecurityEvent event, SecurityDecision decision) {
        if (decision != null &&
            (decision.getAction() == SecurityDecision.Action.BLOCK ||
             decision.getAction() == SecurityDecision.Action.ESCALATE)) {
            onSecurityEvent(event);
        }
    }
    
    
    default void onNetworkEvent(SecurityEvent event) {
        
        onSecurityEvent(event);
    }

    
    default void onAuthenticationEvent(SecurityEvent event) {
        
        onSecurityEvent(event);
    }
    
    
    @Deprecated(since = "4.0.0", forRemoval = true)
    default void onMalwareEvent(SecurityEvent event) {
        
        onSecurityEvent(event);
    }

    
    @Deprecated(since = "4.0.0", forRemoval = true)
    default void onAnomalyEvent(SecurityEvent event) {
        
        onSecurityEvent(event);
    }

    
    @Deprecated(since = "4.0.0", forRemoval = true)
    default void onPolicyViolationEvent(SecurityEvent event) {
        
        onSecurityEvent(event);
    }

    
    default void onError(SecurityEvent event, Exception e) {
        
        log.error("[SecurityEventListener] Error processing event {}: {}", event.getEventId(), e.getMessage(), e);
    }

    
    
    
    
    
    default boolean canHandle(SecurityEvent.EventSource source) {
        return true; 
    }
    
    
    default int getPriority() {
        return 100;
    }
    
    
    default boolean isActive() {
        return true;
    }
}