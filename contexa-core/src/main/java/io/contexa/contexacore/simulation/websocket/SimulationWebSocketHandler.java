package io.contexa.contexacore.simulation.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.domain.entity.AttackResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * WebSocket 핸들러 - 실시간 시뮬레이션 모니터링
 * 
 * 공격 시뮬레이션 결과를 실시간으로 클라이언트에 스트리밍합니다.
 * 각 세션별로 구독을 관리하고 이벤트를 브로드캐스트합니다.
 */
@Component
public class SimulationWebSocketHandler extends TextWebSocketHandler {
    private static final Logger logger = LoggerFactory.getLogger(SimulationWebSocketHandler.class);
    
    // 연결된 세션 관리
    private final Map<String, WebSocketSession> sessions = new ConcurrentHashMap<>();
    
    // 캠페인별 구독자 관리
    private final Map<String, Set<String>> campaignSubscribers = new ConcurrentHashMap<>();
    
    // JSON 변환
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    // 하트비트 스케줄러
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    
    /**
     * WebSocket 연결 수립
     */
    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        String sessionId = session.getId();
        sessions.put(sessionId, session);
        
        logger.info("WebSocket 연결 수립: {}", sessionId);
        
        // 환영 메시지 전송
        sendMessage(session, createMessage("connection", Map.of(
            "status", "connected",
            "sessionId", sessionId,
            "timestamp", LocalDateTime.now().toString()
        )));
        
        // 하트비트 시작 (30초마다)
        scheduler.scheduleAtFixedRate(() -> {
            if (session.isOpen()) {
                try {
                    sendMessage(session, createMessage("heartbeat", Map.of(
                        "timestamp", System.currentTimeMillis()
                    )));
                } catch (Exception e) {
                    logger.error("하트비트 전송 실패: {}", e.getMessage());
                }
            }
        }, 30, 30, TimeUnit.SECONDS);
    }
    
    /**
     * 메시지 수신 처리
     */
    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        String sessionId = session.getId();
        String payload = message.getPayload();
        
        logger.debug("메시지 수신 [{}]: {}", sessionId, payload);
        
        try {
            Map<String, Object> data = objectMapper.readValue(payload, Map.class);
            String type = (String) data.get("type");
            
            switch (type) {
                case "subscribe_campaign":
                    subscribeToCampaign(sessionId, (String) data.get("campaignId"));
                    break;
                    
                case "unsubscribe_campaign":
                    unsubscribeFromCampaign(sessionId, (String) data.get("campaignId"));
                    break;
                    
                case "get_metrics":
                    sendMetrics(session);
                    break;
                    
                case "ping":
                    sendMessage(session, createMessage("pong", Map.of(
                        "timestamp", System.currentTimeMillis()
                    )));
                    break;
                    
                default:
                    logger.warn("알 수 없는 메시지 타입: {}", type);
            }
        } catch (Exception e) {
            logger.error("메시지 처리 오류: {}", e.getMessage(), e);
            sendError(session, "메시지 처리 실패: " + e.getMessage());
        }
    }
    
    /**
     * 연결 종료 처리
     */
    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
        String sessionId = session.getId();
        sessions.remove(sessionId);
        
        // 모든 구독 해제
        campaignSubscribers.values().forEach(subscribers -> subscribers.remove(sessionId));
        
        logger.info("WebSocket 연결 종료 [{}]: {}", sessionId, status.toString());
    }
    
    /**
     * 오류 처리
     */
    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) throws Exception {
        logger.error("WebSocket 전송 오류 [{}]: {}", session.getId(), exception.getMessage(), exception);
        
        if (session.isOpen()) {
            sendError(session, "전송 오류: " + exception.getMessage());
        }
    }
    
    /**
     * 공격 시작 이벤트 브로드캐스트
     */
    public void broadcastAttackStarted(String campaignId, AttackResult result) {
        Map<String, Object> eventData = Map.of(
            "attackId", result.getAttackId(),
            "attackType", result.getType() != null ? result.getType().name() : "UNKNOWN",
            "targetUser", result.getTargetUser(),
            "timestamp", LocalDateTime.now().toString()
        );
        
        broadcastToCampaign(campaignId, "attack_started", eventData);
        broadcastToAll("attack_started", eventData);
    }
    
    /**
     * 공격 탐지 이벤트 브로드캐스트
     */
    public void broadcastAttackDetected(String campaignId, AttackResult result) {
        Map<String, Object> eventData = new HashMap<>();
        eventData.put("attackId", result.getAttackId());
        eventData.put("attackType", result.getType() != null ? result.getType().name() : "UNKNOWN");
        eventData.put("detected", result.isDetected());
        eventData.put("responseTime", result.getDetectionTimeMs());
        eventData.put("riskLevel", result.getRiskLevel());
        eventData.put("riskScore", result.getRiskScore());
        
        broadcastToCampaign(campaignId, "attack_detected", eventData);
        broadcastToAll("attack_detected", eventData);
    }
    
    /**
     * 공격 차단 이벤트 브로드캐스트
     */
    public void broadcastAttackMitigated(String campaignId, AttackResult result) {
        Map<String, Object> eventData = Map.of(
            "attackId", result.getAttackId(),
            "attackType", result.getType() != null ? result.getType().name() : "UNKNOWN",
            "blocked", result.isBlocked(),
            "policy", result.getTriggeredPolicies().isEmpty() ? "DEFAULT" : 
                     result.getTriggeredPolicies().get(0),
            "timestamp", LocalDateTime.now().toString()
        );
        
        broadcastToCampaign(campaignId, "attack_mitigated", eventData);
        broadcastToAll("attack_mitigated", eventData);
    }
    
    /**
     * 메트릭 업데이트 브로드캐스트
     */
    public void broadcastMetricsUpdate(Map<String, Object> metrics) {
        broadcastToAll("metrics_update", metrics);
    }
    
    /**
     * 로그 메시지 브로드캐스트
     */
    public void broadcastLog(String content, String level) {
        Map<String, Object> logData = Map.of(
            "content", content,
            "level", level,
            "timestamp", LocalDateTime.now().toString()
        );
        
        broadcastToAll("log", logData);
    }
    
    /**
     * 캠페인 구독
     */
    private void subscribeToCampaign(String sessionId, String campaignId) {
        campaignSubscribers.computeIfAbsent(campaignId, k -> ConcurrentHashMap.newKeySet())
                          .add(sessionId);
        
        logger.info("세션 [{}]이 캠페인 [{}] 구독", sessionId, campaignId);
        
        WebSocketSession session = sessions.get(sessionId);
        if (session != null) {
            sendMessage(session, createMessage("subscribed", Map.of(
                "campaignId", campaignId,
                "status", "success"
            )));
        }
    }
    
    /**
     * 캠페인 구독 해제
     */
    private void unsubscribeFromCampaign(String sessionId, String campaignId) {
        Set<String> subscribers = campaignSubscribers.get(campaignId);
        if (subscribers != null) {
            subscribers.remove(sessionId);
        }
        
        logger.info("세션 [{}]이 캠페인 [{}] 구독 해제", sessionId, campaignId);
    }
    
    /**
     * 캠페인 구독자에게 브로드캐스트
     */
    private void broadcastToCampaign(String campaignId, String type, Map<String, Object> data) {
        Set<String> subscribers = campaignSubscribers.get(campaignId);
        if (subscribers == null || subscribers.isEmpty()) {
            return;
        }
        
        String message = createMessage(type, data);
        
        subscribers.forEach(sessionId -> {
            WebSocketSession session = sessions.get(sessionId);
            if (session != null && session.isOpen()) {
                sendMessage(session, message);
            }
        });
    }
    
    /**
     * 모든 세션에 브로드캐스트
     */
    private void broadcastToAll(String type, Map<String, Object> data) {
        String message = createMessage(type, data);
        
        sessions.values().forEach(session -> {
            if (session.isOpen()) {
                sendMessage(session, message);
            }
        });
    }
    
    /**
     * 메트릭 전송
     */
    private void sendMetrics(WebSocketSession session) {
        // 실제 메트릭 수집 (여기서는 샘플 데이터)
        Map<String, Object> metrics = Map.of(
            "totalAttacks", sessions.size() * 10,
            "detectionRate", 0.85,
            "avgResponseTime", 250,
            "activeAttacks", 3
        );
        
        sendMessage(session, createMessage("metrics_update", metrics));
    }
    
    /**
     * 오류 메시지 전송
     */
    private void sendError(WebSocketSession session, String error) {
        sendMessage(session, createMessage("error", Map.of(
            "message", error,
            "timestamp", LocalDateTime.now().toString()
        )));
    }
    
    /**
     * 메시지 생성
     */
    private String createMessage(String type, Map<String, Object> data) {
        try {
            Map<String, Object> message = new HashMap<>();
            message.put("type", type);
            message.put("data", data);
            message.put("timestamp", System.currentTimeMillis());
            
            return objectMapper.writeValueAsString(message);
        } catch (Exception e) {
            logger.error("메시지 생성 실패: {}", e.getMessage());
            return "{}";
        }
    }
    
    /**
     * 메시지 전송
     */
    private void sendMessage(WebSocketSession session, String message) {
        try {
            if (session.isOpen()) {
                session.sendMessage(new TextMessage(message));
            }
        } catch (IOException e) {
            logger.error("메시지 전송 실패 [{}]: {}", session.getId(), e.getMessage());
        }
    }
    
    /**
     * 활성 세션 수 조회
     */
    public int getActiveSessionCount() {
        return sessions.size();
    }
    
    /**
     * 캠페인 구독자 수 조회
     */
    public int getCampaignSubscriberCount(String campaignId) {
        Set<String> subscribers = campaignSubscribers.get(campaignId);
        return subscribers != null ? subscribers.size() : 0;
    }
}