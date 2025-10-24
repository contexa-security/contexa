package io.contexa.contexacore.simulation.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.simulation.orchestrator.SimulationOrchestrator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.messaging.simp.annotation.SendToUser;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Controller;
import org.springframework.web.socket.messaging.SessionConnectEvent;
import org.springframework.web.socket.messaging.SessionDisconnectEvent;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 시뮬레이션 WebSocket 컨트롤러
 * 
 * 실시간 공격 모니터링과 상태 업데이트를 위한 WebSocket 엔드포인트를 제공합니다.
 * STOMP 프로토콜을 사용하여 양방향 통신을 구현합니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class SimulationWebSocketController {
    
    private final SimpMessagingTemplate messagingTemplate;
    private final SimulationOrchestrator orchestrator;
    private final ObjectMapper objectMapper;
    
    // 연결된 클라이언트 추적
    private final Map<String, ClientSession> connectedClients = new ConcurrentHashMap<>();
    private final AtomicInteger connectionCount = new AtomicInteger(0);
    
    /**
     * WebSocket 연결 이벤트 처리
     */
    @EventListener
    public void handleWebSocketConnectListener(SessionConnectEvent event) {
        String sessionId = event.getMessage().getHeaders().get("simpSessionId").toString();
        log.info("WebSocket 연결 수립: sessionId={}", sessionId);
        
        ClientSession session = new ClientSession(sessionId, LocalDateTime.now());
        connectedClients.put(sessionId, session);
        connectionCount.incrementAndGet();
        
        // 연결 알림 전송
        sendConnectionStatus(sessionId, true);
    }
    
    /**
     * WebSocket 연결 해제 이벤트 처리
     */
    @EventListener
    public void handleWebSocketDisconnectListener(SessionDisconnectEvent event) {
        String sessionId = event.getSessionId();
        log.info("WebSocket 연결 해제: sessionId={}", sessionId);
        
        connectedClients.remove(sessionId);
        connectionCount.decrementAndGet();
        
        // 연결 해제 알림 전송
        sendConnectionStatus(sessionId, false);
    }
    
    /**
     * 메트릭 요청 처리
     */
    @MessageMapping("/get_metrics")
    @SendToUser("/topic/metrics")
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        try {
            metrics.put("type", "metrics_update");
            metrics.put("data", Map.of(
                "totalAttacks", orchestrator.getTotalAttacks(),
                "detectedAttacks", orchestrator.getDetectedAttacks(),
                "activeAttacks", orchestrator.getActiveAttacks(),
                "detectionRate", orchestrator.getDetectionRate(),
                "avgResponseTime", orchestrator.getAverageResponseTime(),
                "timestamp", LocalDateTime.now().toString()
            ));
        } catch (Exception e) {
            log.error("메트릭 조회 실패: {}", e.getMessage(), e);
            metrics.put("type", "error");
            metrics.put("message", e.getMessage());
        }
        
        return metrics;
    }
    
    /**
     * 공격 시작 알림 전송
     */
    public void notifyAttackStarted(String attackId, String attackType, String targetUser) {
        Map<String, Object> message = new HashMap<>();
        message.put("type", "attack_started");
        message.put("attackId", attackId);
        message.put("attackType", attackType);
        message.put("targetUser", targetUser);
        message.put("timestamp", LocalDateTime.now().toString());
        
        broadcast("/topic/attacks", message);
    }
    
    /**
     * 공격 탐지 알림 전송
     */
    public void notifyAttackDetected(String attackId, String attackType, long responseTime) {
        Map<String, Object> message = new HashMap<>();
        message.put("type", "attack_detected");
        message.put("attackId", attackId);
        message.put("attackType", attackType);
        message.put("responseTime", responseTime);
        message.put("timestamp", LocalDateTime.now().toString());
        
        broadcast("/topic/detections", message);
    }
    
    /**
     * 공격 차단 알림 전송
     */
    public void notifyAttackMitigated(String attackId, String attackType, String policy) {
        Map<String, Object> message = new HashMap<>();
        message.put("type", "attack_mitigated");
        message.put("attackId", attackId);
        message.put("attackType", attackType);
        message.put("policy", policy);
        message.put("timestamp", LocalDateTime.now().toString());
        
        broadcast("/topic/mitigations", message);
    }
    
    /**
     * 로그 메시지 전송
     */
    public void sendLogMessage(String content, String level) {
        Map<String, Object> message = new HashMap<>();
        message.put("type", "log");
        message.put("content", content);
        message.put("level", level);
        message.put("timestamp", LocalDateTime.now().toString());
        
        broadcast("/topic/logs", message);
    }
    
    /**
     * 캠페인 상태 업데이트
     */
    public void updateCampaignStatus(String campaignId, String status, Map<String, Object> details) {
        Map<String, Object> message = new HashMap<>();
        message.put("type", "campaign_status");
        message.put("campaignId", campaignId);
        message.put("status", status);
        message.put("details", details);
        message.put("timestamp", LocalDateTime.now().toString());
        
        broadcast("/topic/campaigns", message);
    }
    
    /**
     * 실시간 메트릭 브로드캐스트 (5초마다)
     */
//    @Scheduled(fixedDelay = 5000)
    public void broadcastMetrics() {
        if (connectionCount.get() > 0) {
            try {
                Map<String, Object> metrics = new HashMap<>();
                metrics.put("type", "metrics_update");
                metrics.put("data", Map.of(
                    "totalAttacks", orchestrator.getTotalAttacks(),
                    "detectedAttacks", orchestrator.getDetectedAttacks(),
                    "activeAttacks", orchestrator.getActiveAttacks(),
                    "detectionRate", orchestrator.getDetectionRate(),
                    "avgResponseTime", orchestrator.getAverageResponseTime(),
                    "activeCampaigns", orchestrator.getActiveCampaigns(),
                    "connectedClients", connectionCount.get(),
                    "timestamp", LocalDateTime.now().toString()
                ));
                
                broadcast("/topic/metrics", metrics);
            } catch (Exception e) {
                log.error("메트릭 브로드캐스트 실패: {}", e.getMessage());
            }
        }
    }
    
    /**
     * 시스템 상태 브로드캐스트 (10초마다)
     */
//    @Scheduled(fixedDelay = 10000)
    public void broadcastSystemStatus() {
        if (connectionCount.get() > 0) {
            try {
                Map<String, Object> status = new HashMap<>();
                status.put("type", "system_status");
                status.put("data", Map.of(
                    "orchestratorStatus", orchestrator.getStatus(),
                    "queuedAttacks", orchestrator.getQueuedAttacks(),
                    "processingCapacity", orchestrator.getProcessingCapacity(),
                    "systemLoad", orchestrator.getSystemLoad(),
                    "timestamp", LocalDateTime.now().toString()
                ));
                
                broadcast("/topic/status", status);
            } catch (Exception e) {
                log.error("상태 브로드캐스트 실패: {}", e.getMessage());
            }
        }
    }
    
    /**
     * 경고 알림 전송
     */
    public void sendAlert(String severity, String title, String message) {
        Map<String, Object> alert = new HashMap<>();
        alert.put("type", "alert");
        alert.put("severity", severity); // info, warning, error, critical
        alert.put("title", title);
        alert.put("message", message);
        alert.put("timestamp", LocalDateTime.now().toString());
        
        broadcast("/topic/alerts", alert);
    }
    
    /**
     * 진행률 업데이트
     */
    public void updateProgress(String operationId, String operation, int progress, int total) {
        Map<String, Object> progressUpdate = new HashMap<>();
        progressUpdate.put("type", "progress");
        progressUpdate.put("operationId", operationId);
        progressUpdate.put("operation", operation);
        progressUpdate.put("progress", progress);
        progressUpdate.put("total", total);
        progressUpdate.put("percentage", total > 0 ? (progress * 100.0 / total) : 0);
        progressUpdate.put("timestamp", LocalDateTime.now().toString());
        
        broadcast("/topic/progress", progressUpdate);
    }
    
    /**
     * 모든 연결된 클라이언트에게 브로드캐스트
     */
    private void broadcast(String destination, Object message) {
        try {
            messagingTemplate.convertAndSend(destination, message);
        } catch (Exception e) {
            log.error("브로드캐스트 실패: destination={}, error={}", destination, e.getMessage());
        }
    }
    
    /**
     * 특정 사용자에게 메시지 전송
     */
    private void sendToUser(String sessionId, String destination, Object message) {
        try {
            messagingTemplate.convertAndSendToUser(sessionId, destination, message);
        } catch (Exception e) {
            log.error("사용자 메시지 전송 실패: sessionId={}, error={}", sessionId, e.getMessage());
        }
    }
    
    /**
     * 연결 상태 알림
     */
    private void sendConnectionStatus(String sessionId, boolean connected) {
        Map<String, Object> status = new HashMap<>();
        status.put("type", "connection_status");
        status.put("sessionId", sessionId);
        status.put("connected", connected);
        status.put("totalConnections", connectionCount.get());
        status.put("timestamp", LocalDateTime.now().toString());
        
        broadcast("/topic/connections", status);
    }
    
    /**
     * 클라이언트 세션 정보
     */
    private static class ClientSession {
        private final String sessionId;
        private final LocalDateTime connectedAt;
        private LocalDateTime lastActivityAt;
        private int messageCount = 0;
        
        public ClientSession(String sessionId, LocalDateTime connectedAt) {
            this.sessionId = sessionId;
            this.connectedAt = connectedAt;
            this.lastActivityAt = connectedAt;
        }
        
        public void updateActivity() {
            this.lastActivityAt = LocalDateTime.now();
            this.messageCount++;
        }
        
        // Getters
        public String getSessionId() { return sessionId; }
        public LocalDateTime getConnectedAt() { return connectedAt; }
        public LocalDateTime getLastActivityAt() { return lastActivityAt; }
        public int getMessageCount() { return messageCount; }
    }
}