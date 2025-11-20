package io.contexa.contexacoreenterprise.soar.helper;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * WebSocket 설정 헬퍼 클래스
 * 
 * SOAR WebSocket 통신을 위한 엔드포인트 및 설정을 중앙화합니다.
 * 클라이언트와 서버 간의 엔드포인트 불일치 문제를 해결합니다.
 */
@Slf4j
@Component
public class WebSocketConfigHelper {
    
    // 통일된 WebSocket 엔드포인트
    public static final String WEBSOCKET_ENDPOINT = "/ws-soar";
    
    // STOMP 엔드포인트
    public static final String STOMP_ENDPOINT = "/ws-soar";
    
    // 메시지 브로커 프리픽스
    public static final String BROKER_PREFIX = "/topic";
    public static final String USER_PREFIX = "/user";
    public static final String APP_PREFIX = "/app";
    
    // STOMP 대상
    public static final String APPROVAL_TOPIC = "/topic/soar/approvals";
    public static final String SESSION_TOPIC = "/topic/soar/sessions";
    public static final String TOOL_TOPIC_PREFIX = "/topic/soar/tools/";
    public static final String USER_QUEUE_SESSION = "/queue/session";
    
    // STOMP 메시지 매핑
    public static final String MAPPING_APPROVE = "/soar/approve";
    public static final String MAPPING_SESSION_STATUS = "/soar/session/status";
    public static final String MAPPING_SESSION_DETAIL = "/soar/session/detail";
    public static final String MAPPING_SESSIONS_ACTIVE = "/soar/sessions/active";
    public static final String MAPPING_SESSION_CLOSE = "/soar/session/close";
    
    // 타임아웃 설정
    public static final long CONNECTION_TIMEOUT_MS = 10000;  // 10초
    public static final long HEARTBEAT_INTERVAL_MS = 20000;  // 20초
    public static final long DISCONNECT_DELAY_MS = 5000;     // 5초
    
    /**
     * WebSocket 연결 URL 생성
     * 
     * @param host 서버 호스트
     * @param port 서버 포트
     * @return WebSocket 연결 URL
     */
    public String buildWebSocketUrl(String host, int port) {
        return String.format("ws://%s:%d%s", host, port, WEBSOCKET_ENDPOINT);
    }
    
    /**
     * WebSocket 보안 연결 URL 생성
     * 
     * @param host 서버 호스트
     * @param port 서버 포트
     * @return WebSocket 보안 연결 URL
     */
    public String buildSecureWebSocketUrl(String host, int port) {
        return String.format("wss://%s:%d%s", host, port, WEBSOCKET_ENDPOINT);
    }
    
    /**
     * 특정 세션의 도구 실행 토픽 경로 생성
     * 
     * @param sessionId 세션 ID
     * @return 도구 실행 토픽 경로
     */
    public String buildToolTopicPath(String sessionId) {
        return TOOL_TOPIC_PREFIX + sessionId;
    }
    
    /**
     * STOMP 헤더 설정
     * 
     * @return 기본 STOMP 헤더
     */
    public java.util.Map<String, String> getDefaultStompHeaders() {
        java.util.Map<String, String> headers = new java.util.HashMap<>();
        headers.put("heart-beat", String.format("%d,%d", HEARTBEAT_INTERVAL_MS, HEARTBEAT_INTERVAL_MS));
        headers.put("accept-version", "1.2");
        headers.put("content-type", "application/json");
        return headers;
    }
    
    /**
     * WebSocket 설정 정보 로깅
     */
    public void logConfiguration() {
        log.info("WebSocket Configuration:");
        log.info("  - Endpoint: {}", WEBSOCKET_ENDPOINT);
        log.info("  - STOMP Endpoint: {}", STOMP_ENDPOINT);
        log.info("  - Broker Prefix: {}", BROKER_PREFIX);
        log.info("  - App Prefix: {}", APP_PREFIX);
        log.info("  - Connection Timeout: {}ms", CONNECTION_TIMEOUT_MS);
        log.info("  - Heartbeat Interval: {}ms", HEARTBEAT_INTERVAL_MS);
    }
    
    /**
     * 엔드포인트 검증
     * 
     * @param endpoint 검증할 엔드포인트
     * @return 유효한 엔드포인트인지 여부
     */
    public boolean isValidEndpoint(String endpoint) {
        return endpoint != null && 
               (endpoint.equals(WEBSOCKET_ENDPOINT) || 
                endpoint.equals("/ws-soar-approval")); // 이전 버전 호환성
    }
    
    /**
     * 레거시 엔드포인트를 새 엔드포인트로 변환
     * 
     * @param legacyEndpoint 레거시 엔드포인트
     * @return 통일된 엔드포인트
     */
    public String normalizEndpoint(String legacyEndpoint) {
        if ("/ws-soar-approval".equals(legacyEndpoint)) {
            log.debug("레거시 엔드포인트 {} -> {} 변환", legacyEndpoint, WEBSOCKET_ENDPOINT);
            return WEBSOCKET_ENDPOINT;
        }
        return legacyEndpoint;
    }
}