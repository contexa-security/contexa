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

/**
 * WebSocket 테스트 컨트롤러
 *
 * WebSocket 통신 및 승인 요청 테스트를 위한 API 제공
 * 디버깅 및 개발 환경에서 사용
 */
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

    /**
     * 간단한 WebSocket 테스트 - 순수 브로드캐스트만 테스트
     */
    @PostMapping("/simple-broadcast")
    public ResponseEntity<?> testSimpleBroadcast(@RequestBody Map<String, String> request) {
        String message = request.getOrDefault("message", "Test Message " + System.currentTimeMillis());

        log.info("🧪 간단한 WebSocket 브로드캐스트 테스트 시작: {}", message);

        try {
            // WebSocketApprovalHandler의 테스트 메서드 호출
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

    /**
     * WebSocket 연결 상태 확인
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getWebSocketStatus() {
        Map<String, Object> status = new HashMap<>();

        try {
            // WebSocket 핸들러 상태
            status.put("handlerAvailable", webSocketApprovalHandler != null);
            status.put("activeSessionCount", webSocketApprovalHandler != null ?
                webSocketApprovalHandler.getActiveSessionCount() : 0);

            // Messaging Template 상태
            status.put("messagingTemplateAvailable", brokerTemplate != null);

            // Notification Service 상태
            status.put("notificationServiceAvailable", notificationService != null);

            // 현재 시간
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

    /**
     * 테스트 승인 요청 트리거
     *
     * @param riskLevel 위험도 레벨 (LOW, MEDIUM, HIGH, CRITICAL)
     * @param approvalId 클라이언트가 제공한 승인 ID (선택사항) - Race Condition 해결용
     * @param sessionId 클라이언트의 실제 세션 ID - 세션 일치를 위해 필수
     * @return 승인 요청 전송 결과
     */
    @PostMapping("/trigger-approval")
    public ResponseEntity<Map<String, Object>> triggerTestApproval(
            @RequestParam(defaultValue = "HIGH") String riskLevel,
            @RequestParam(required = false) String approvalId,
            @RequestParam(required = false) String sessionId) {

        Map<String, Object> response = new HashMap<>();

        try {
            // 클라이언트가 제공한 ID를 사용하거나 새로 생성 (GPT 솔루션)
            if (approvalId == null || approvalId.isBlank()) {
                approvalId = "TEST-" + UUID.randomUUID().toString();
            }
            log.info("승인 요청 ID: {} (클라이언트 제공: {}, sessionId: {})",
                approvalId, approvalId.startsWith("TEST-") && approvalId.contains("-"), sessionId);

            ApprovalRequest request = createTestApprovalRequest(approvalId, riskLevel, sessionId);

            log.info("🔔 Triggering test approval request: {}", approvalId);

            // WebSocket 으로 승인 요청 전송
            if (webSocketApprovalHandler != null) {
                webSocketApprovalHandler.sendApprovalRequest(request);
                log.info("Approval request sent via WebSocketApprovalHandler");
            }

            // Notification Service로도 전송 (이중 전송으로 확실하게)
            if (notificationService != null) {
                notificationService.sendApprovalRequest(request);
                log.info("Approval request sent via NotificationService");
            }

            // 토픽 사전 활성화 - 동적 토픽이 구독 가능하도록 미리 빈 메시지 전송
            String resultTopic = "/topic/soar/approval-results/" + approvalId;
            Map<String, Object> initMessage = new HashMap<>();
            initMessage.put("type", "TOPIC_INIT");
            initMessage.put("approvalId", approvalId);
            initMessage.put("timestamp", LocalDateTime.now());
            brokerTemplate.convertAndSend(resultTopic, initMessage);
            log.info("토픽 사전 활성화: {}", resultTopic);
            
            // 짧은 지연을 주어 토픽이 활성화되도록 함
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            // 직접 STOMP 메시지 전송 (테스트용)
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

    /**
     * 테스트 브로드캐스트 메시지 전송
     */
    @PostMapping("/broadcast")
    public ResponseEntity<Map<String, Object>> broadcastTestMessage(
            @RequestBody Map<String, Object> message) {

        Map<String, Object> response = new HashMap<>();

        try {
            // /topic/soar/approvals로 메시지 브로드캐스트
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

    /**
     * 간단한 테스트 메시지 전송
     */
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

    /**
     * 테스트 승인 요청 생성
     */
    private ApprovalRequest createTestApprovalRequest(String approvalId, String riskLevel, String sessionId) {
        ApprovalRequest request = new ApprovalRequest();

        request.setRequestId(approvalId);
        request.setToolName("Test Security Scan Tool");
        request.setToolDescription("This is a test approval request for WebSocket communication verification");
        request.setActionDescription("Execute security vulnerability scan on production servers");

        // 위험도 설정
        try {
            request.setRiskLevel(ApprovalRequest.RiskLevel.valueOf(riskLevel.toUpperCase()));
        } catch (IllegalArgumentException e) {
            request.setRiskLevel(ApprovalRequest.RiskLevel.HIGH);
        }

        // 파라미터 설정
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("scanType", "FULL_SCAN");
        parameters.put("targetServers", new String[]{"server1", "server2", "server3"});
        parameters.put("estimatedDuration", "15 minutes");
        parameters.put("requiresDowntime", false);
        request.setParameters(parameters);

        // 메타데이터 설정
        request.setRequestedBy("Test System");
        request.setRequestedAt(LocalDateTime.now());
        request.setOrganizationId("test-org");
        // 클라이언트가 제공한 세션 ID를 사용, 없으면 기본값 사용
        if (sessionId != null && !sessionId.isBlank()) {
            request.setSessionId(sessionId);
        } else {
            request.setSessionId("test-session-" + System.currentTimeMillis());
        }
        request.setIncidentId("INC-TEST-001");
        request.setStatus(ApprovalRequest.ApprovalStatus.PENDING);

        return request;
    }

    /**
     * 직접 STOMP 메시지 전송 (테스트용)
     */
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

            // 다양한 토픽으로 전송하여 확실하게 전달
            brokerTemplate.convertAndSend("/topic/soar/approvals", message);
            log.info("Direct STOMP message sent to /topic/soar/approvals");

            brokerTemplate.convertAndSend("/topic/soar/events", message);
            log.info("Direct STOMP message sent to /topic/soar/events");

        } catch (Exception e) {
            log.error("Failed to send direct STOMP message", e);
        }
    }
}