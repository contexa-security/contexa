package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacoreenterprise.soar.approval.McpApprovalNotificationService;
import io.contexa.contexacoreenterprise.soar.event.WebSocketApprovalHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


@Slf4j
@RequestMapping("/api/test/websocket")
public class WebSocketTestRestController {

    private final WebSocketApprovalHandler webSocketApprovalHandler;
    private final McpApprovalNotificationService notificationService;
    private final SimpMessagingTemplate brokerTemplate;

    public WebSocketTestRestController(WebSocketApprovalHandler webSocketApprovalHandler,
                                       McpApprovalNotificationService notificationService,
                                       @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        this.webSocketApprovalHandler = webSocketApprovalHandler;
        this.notificationService = notificationService;
        this.brokerTemplate = brokerTemplate;
    }

    
    @PostMapping("/simple-broadcast")
    public ResponseEntity<?> testSimpleBroadcast(@RequestBody Map<String, String> request) {
        String message = request.getOrDefault("message", "Test Message " + System.currentTimeMillis());

        log.info("🧪 간단한 WebSocket 브로드캐스트 테스트 시작: {}", message);

        try {
            
            webSocketApprovalHandler.sendTestBroadcast(message);

            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "테스트 브로드캐스트 전송 완료",
                "testMessage", message,
                "timestamp", LocalDateTime.now()
            ));
        } catch (Exception e) {
            log.error("테스트 브로드캐스트 실패", e);
            return ResponseEntity.status(500).body(Map.of(
                "success", false,
                "error", e.getMessage()
            ));
        }
    }

    
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getWebSocketStatus() {
        Map<String, Object> status = new HashMap<>();

        try {
            
            status.put("handlerAvailable", webSocketApprovalHandler != null);
            status.put("activeSessionCount", webSocketApprovalHandler != null ?
                webSocketApprovalHandler.getActiveSessionCount() : 0);

            
            status.put("messagingTemplateAvailable", brokerTemplate != null);

            
            status.put("notificationServiceAvailable", notificationService != null);

            
            status.put("timestamp", LocalDateTime.now());
            status.put("status", "OK");

            log.info("WebSocket status check: {}", status);
            return ResponseEntity.ok(status);

        } catch (Exception e) {
            log.error("Error checking WebSocket status", e);
            status.put("status", "ERROR");
            status.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(status);
        }
    }

    
    @PostMapping("/trigger-approval")
    public ResponseEntity<Map<String, Object>> triggerTestApproval(
            @RequestParam(defaultValue = "HIGH") String riskLevel,
            @RequestParam(required = false) String approvalId,
            @RequestParam(required = false) String sessionId) {

        Map<String, Object> response = new HashMap<>();

        try {
            
            if (approvalId == null || approvalId.isBlank()) {
                approvalId = "TEST-" + UUID.randomUUID().toString();
            }
            log.info("승인 요청 ID: {} (클라이언트 제공: {}, sessionId: {})",
                approvalId, approvalId.startsWith("TEST-") && approvalId.contains("-"), sessionId);

            ApprovalRequest request = createTestApprovalRequest(approvalId, riskLevel, sessionId);

            log.info("🔔 Triggering test approval request: {}", approvalId);

            
            if (webSocketApprovalHandler != null) {
                webSocketApprovalHandler.sendApprovalRequest(request);
                log.info("Approval request sent via WebSocketApprovalHandler");
            }

            
            if (notificationService != null) {
                notificationService.sendApprovalRequest(request);
                log.info("Approval request sent via NotificationService");
            }

            
            String resultTopic = "/topic/soar/approval-results/" + approvalId;
            Map<String, Object> initMessage = new HashMap<>();
            initMessage.put("type", "TOPIC_INIT");
            initMessage.put("approvalId", approvalId);
            initMessage.put("timestamp", LocalDateTime.now());
            brokerTemplate.convertAndSend(resultTopic, initMessage);
            log.info("토픽 사전 활성화: {}", resultTopic);
            
            
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            
            sendDirectStompMessage(request);

            response.put("success", true);
            response.put("approvalId", approvalId);
            response.put("message", "Test approval request sent successfully");
            response.put("timestamp", LocalDateTime.now());
            response.put("handlers", Map.of(
                "webSocketHandler", webSocketApprovalHandler != null,
                "notificationService", notificationService != null
            ));

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Failed to trigger test approval", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    
    @PostMapping("/broadcast")
    public ResponseEntity<Map<String, Object>> broadcastTestMessage(
            @RequestBody Map<String, Object> message) {

        Map<String, Object> response = new HashMap<>();

        try {
            
            brokerTemplate.convertAndSend("/topic/soar/approvals", message);
            log.info("Broadcast message sent to /topic/soar/approvals");

            response.put("success", true);
            response.put("message", "Broadcast sent successfully");
            response.put("topic", "/topic/soar/approvals");
            response.put("payload", message);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Failed to broadcast message", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    
    @GetMapping("/ping")
    public ResponseEntity<Map<String, Object>> sendPing() {
        Map<String, Object> pingMessage = new HashMap<>();
        pingMessage.put("type", "PING");
        pingMessage.put("timestamp", LocalDateTime.now());
        pingMessage.put("message", "WebSocket connection test");

        try {
            brokerTemplate.convertAndSend("/topic/soar/approvals", pingMessage);
            log.info("Ping message sent");

            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Ping sent",
                "timestamp", LocalDateTime.now()
            ));

        } catch (Exception e) {
            log.error("Failed to send ping", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "success", false,
                "error", e.getMessage()
            ));
        }
    }

    
    private ApprovalRequest createTestApprovalRequest(String approvalId, String riskLevel, String sessionId) {
        ApprovalRequest request = new ApprovalRequest();

        request.setRequestId(approvalId);
        request.setToolName("Test Security Scan Tool");
        request.setToolDescription("This is a test approval request for WebSocket communication verification");
        request.setActionDescription("Execute security vulnerability scan on production servers");

        
        try {
            request.setRiskLevel(ApprovalRequest.RiskLevel.valueOf(riskLevel.toUpperCase()));
        } catch (IllegalArgumentException e) {
            request.setRiskLevel(ApprovalRequest.RiskLevel.HIGH);
        }

        
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("scanType", "FULL_SCAN");
        parameters.put("targetServers", new String[]{"server1", "server2", "server3"});
        parameters.put("estimatedDuration", "15 minutes");
        parameters.put("requiresDowntime", false);
        request.setParameters(parameters);

        
        request.setRequestedBy("Test System");
        request.setRequestedAt(LocalDateTime.now());
        request.setOrganizationId("test-org");
        
        if (sessionId != null && !sessionId.isBlank()) {
            request.setSessionId(sessionId);
        } else {
            request.setSessionId("test-session-" + System.currentTimeMillis());
        }
        request.setIncidentId("INC-TEST-001");
        request.setStatus(ApprovalRequest.ApprovalStatus.PENDING);

        return request;
    }

    
    private void sendDirectStompMessage(ApprovalRequest request) {
        try {
            Map<String, Object> message = new HashMap<>();
            message.put("type", "APPROVAL_REQUEST");
            message.put("approvalId", request.getRequestId());
            message.put("requestId", request.getRequestId());
            message.put("toolName", request.getToolName());
            message.put("description", request.getToolDescription());
            message.put("riskLevel", request.getRiskLevel().name());
            message.put("requestedBy", request.getRequestedBy());
            message.put("timestamp", LocalDateTime.now());
            message.put("parameters", request.getParameters());

            
            brokerTemplate.convertAndSend("/topic/soar/approvals", message);
            log.info("Direct STOMP message sent to /topic/soar/approvals");

            brokerTemplate.convertAndSend("/topic/soar/events", message);
            log.info("Direct STOMP message sent to /topic/soar/events");

        } catch (Exception e) {
            log.error("Failed to send direct STOMP message", e);
        }
    }
}