package io.contexa.contexaiam.aiam.listener;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.web.socket.messaging.*;

/**
 * WebSocket/STOMP 이벤트 리스너
 * 
 * 연결, 구독, 메시지 전송, 연결 해제 등 모든 WebSocket 이벤트를 로깅
 * 디버깅 및 모니터링을 위한 상세한 이벤트 추적 제공
 */
@Slf4j
public class StompEventListener {

    /**
     * WebSocket 연결 이벤트 리스너
     */
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

    /**
     * WebSocket 연결 해제 이벤트 리스너
     */
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

    /**
     * WebSocket 구독 이벤트 리스너
     */
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

    /**
     * WebSocket 구독 해제 이벤트 리스너
     */
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

    /**
     * WebSocket 연결 실패 이벤트 리스너
     */
    public static class StompConnectFailureEventListener implements ApplicationListener<SessionConnectEvent> {
        @Override
        public void onApplicationEvent(SessionConnectEvent event) {
            StompHeaderAccessor headerAccessor = StompHeaderAccessor.wrap(event.getMessage());
            String sessionId = headerAccessor.getSessionId();
            
            // 연결 시작 이벤트만 로깅 (실패는 별도 이벤트로 처리)
            log.info("WebSocket Connection Attempt - Session ID: {}", sessionId);
            log.debug("Connect Event Details - User: {}, Headers: {}", 
                headerAccessor.getUser(),
                headerAccessor.toNativeHeaderMap());
        }
    }

    /**
     * 세션 속성 조회를 위한 헬퍼 메서드
     */
    private static String getSessionAttributes(StompHeaderAccessor headerAccessor) {
        if (headerAccessor.getSessionAttributes() != null) {
            return headerAccessor.getSessionAttributes().toString();
        }
        return "N/A";
    }

    /**
     * 연결 상태 요약 정보 생성
     */
    private static String getConnectionSummary(StompHeaderAccessor headerAccessor) {
        return String.format("Session: %s, User: %s, Destination: %s",
            headerAccessor.getSessionId(),
            headerAccessor.getUser() != null ? headerAccessor.getUser().getName() : "Anonymous",
            headerAccessor.getDestination() != null ? headerAccessor.getDestination() : "N/A"
        );
    }
}