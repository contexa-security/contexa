package io.contexa.contexaiam.aiam.listener;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.web.socket.messaging.*;


@Slf4j
public class StompEventListener {

    
    public static class StompConnectedEventListener implements ApplicationListener<SessionConnectedEvent> {
        @Override
        public void onApplicationEvent(SessionConnectedEvent event) {
            StompHeaderAccessor headerAccessor = StompHeaderAccessor.wrap(event.getMessage());
            String sessionId = headerAccessor.getSessionId();
            
            log.info("🔗 WebSocket Connected - Session ID: {}", sessionId);
            log.debug("Connected Event Details - User: {}, Headers: {}", 
                headerAccessor.getUser(), 
                headerAccessor.toNativeHeaderMap());
        }
    }

    
    public static class StompDisconnectEventListener implements ApplicationListener<SessionDisconnectEvent> {
        @Override
        public void onApplicationEvent(SessionDisconnectEvent event) {
            StompHeaderAccessor headerAccessor = StompHeaderAccessor.wrap(event.getMessage());
            String sessionId = headerAccessor.getSessionId();
            
            log.info("🔌 WebSocket Disconnected - Session ID: {}", sessionId);
            log.debug("Disconnect Event Details - User: {}, Close Status: {}", 
                headerAccessor.getUser(),
                event.getCloseStatus());
        }
    }

    
    public static class StompSubscribeEventListener implements ApplicationListener<SessionSubscribeEvent> {
        @Override
        public void onApplicationEvent(SessionSubscribeEvent event) {
            StompHeaderAccessor headerAccessor = StompHeaderAccessor.wrap(event.getMessage());
            String sessionId = headerAccessor.getSessionId();
            String destination = headerAccessor.getDestination();
            String subscriptionId = headerAccessor.getSubscriptionId();
            
            log.info("WebSocket Subscribe - Session: {}, Destination: {}, Subscription ID: {}", 
                sessionId, destination, subscriptionId);
            log.debug("Subscribe Event Details - User: {}, Headers: {}", 
                headerAccessor.getUser(),
                headerAccessor.toNativeHeaderMap());
        }
    }

    
    public static class StompUnsubscribeEventListener implements ApplicationListener<SessionUnsubscribeEvent> {
        @Override
        public void onApplicationEvent(SessionUnsubscribeEvent event) {
            StompHeaderAccessor headerAccessor = StompHeaderAccessor.wrap(event.getMessage());
            String sessionId = headerAccessor.getSessionId();
            String subscriptionId = headerAccessor.getSubscriptionId();
            
            log.info("📴 WebSocket Unsubscribe - Session: {}, Subscription ID: {}", 
                sessionId, subscriptionId);
            log.debug("Unsubscribe Event Details - User: {}, Headers: {}", 
                headerAccessor.getUser(),
                headerAccessor.toNativeHeaderMap());
        }
    }

    
    public static class StompConnectFailureEventListener implements ApplicationListener<SessionConnectEvent> {
        @Override
        public void onApplicationEvent(SessionConnectEvent event) {
            StompHeaderAccessor headerAccessor = StompHeaderAccessor.wrap(event.getMessage());
            String sessionId = headerAccessor.getSessionId();
            
            
            log.info("WebSocket Connection Attempt - Session ID: {}", sessionId);
            log.debug("Connect Event Details - User: {}, Headers: {}", 
                headerAccessor.getUser(),
                headerAccessor.toNativeHeaderMap());
        }
    }

    
    private static String getSessionAttributes(StompHeaderAccessor headerAccessor) {
        if (headerAccessor.getSessionAttributes() != null) {
            return headerAccessor.getSessionAttributes().toString();
        }
        return "N/A";
    }

    
    private static String getConnectionSummary(StompHeaderAccessor headerAccessor) {
        return String.format("Session: %s, User: %s, Destination: %s",
            headerAccessor.getSessionId(),
            headerAccessor.getUser() != null ? headerAccessor.getUser().getName() : "Anonymous",
            headerAccessor.getDestination() != null ? headerAccessor.getDestination() : "N/A"
        );
    }
}