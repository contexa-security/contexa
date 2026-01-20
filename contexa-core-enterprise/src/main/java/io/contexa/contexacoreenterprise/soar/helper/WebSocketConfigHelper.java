package io.contexa.contexacoreenterprise.soar.helper;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public class WebSocketConfigHelper {
    
    
    public static final String WEBSOCKET_ENDPOINT = "/ws-soar";
    
    
    public static final String STOMP_ENDPOINT = "/ws-soar";
    
    
    public static final String BROKER_PREFIX = "/topic";
    public static final String USER_PREFIX = "/user";
    public static final String APP_PREFIX = "/app";
    
    
    public static final String APPROVAL_TOPIC = "/topic/soar/approvals";
    public static final String SESSION_TOPIC = "/topic/soar/sessions";
    public static final String TOOL_TOPIC_PREFIX = "/topic/soar/tools/";
    public static final String USER_QUEUE_SESSION = "/queue/session";
    
    
    public static final String MAPPING_APPROVE = "/soar/approve";
    public static final String MAPPING_SESSION_STATUS = "/soar/session/status";
    public static final String MAPPING_SESSION_DETAIL = "/soar/session/detail";
    public static final String MAPPING_SESSIONS_ACTIVE = "/soar/sessions/active";
    public static final String MAPPING_SESSION_CLOSE = "/soar/session/close";
    
    
    public static final long CONNECTION_TIMEOUT_MS = 10000;  
    public static final long HEARTBEAT_INTERVAL_MS = 20000;  
    public static final long DISCONNECT_DELAY_MS = 5000;     
    
    
    public String buildWebSocketUrl(String host, int port) {
        return String.format("ws://%s:%d%s", host, port, WEBSOCKET_ENDPOINT);
    }
    
    
    public String buildSecureWebSocketUrl(String host, int port) {
        return String.format("wss://%s:%d%s", host, port, WEBSOCKET_ENDPOINT);
    }
    
    
    public String buildToolTopicPath(String sessionId) {
        return TOOL_TOPIC_PREFIX + sessionId;
    }
    
    
    public java.util.Map<String, String> getDefaultStompHeaders() {
        java.util.Map<String, String> headers = new java.util.HashMap<>();
        headers.put("heart-beat", String.format("%d,%d", HEARTBEAT_INTERVAL_MS, HEARTBEAT_INTERVAL_MS));
        headers.put("accept-version", "1.2");
        headers.put("content-type", "application/json");
        return headers;
    }
    
    
    public void logConfiguration() {
        log.info("WebSocket Configuration:");
        log.info("  - Endpoint: {}", WEBSOCKET_ENDPOINT);
        log.info("  - STOMP Endpoint: {}", STOMP_ENDPOINT);
        log.info("  - Broker Prefix: {}", BROKER_PREFIX);
        log.info("  - App Prefix: {}", APP_PREFIX);
        log.info("  - Connection Timeout: {}ms", CONNECTION_TIMEOUT_MS);
        log.info("  - Heartbeat Interval: {}ms", HEARTBEAT_INTERVAL_MS);
    }
    
    
    public boolean isValidEndpoint(String endpoint) {
        return endpoint != null && 
               (endpoint.equals(WEBSOCKET_ENDPOINT) || 
                endpoint.equals("/ws-soar-approval")); 
    }
    
    
    public String normalizEndpoint(String legacyEndpoint) {
        if ("/ws-soar-approval".equals(legacyEndpoint)) {
            log.debug("레거시 엔드포인트 {} -> {} 변환", legacyEndpoint, WEBSOCKET_ENDPOINT);
            return WEBSOCKET_ENDPOINT;
        }
        return legacyEndpoint;
    }
}