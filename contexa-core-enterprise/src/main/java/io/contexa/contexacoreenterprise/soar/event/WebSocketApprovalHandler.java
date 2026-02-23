package io.contexa.contexacoreenterprise.soar.event;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacoreenterprise.soar.approval.UnifiedApprovalService;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.messaging.handler.annotation.DestinationVariable;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.messaging.simp.annotation.SendToUser;
import org.springframework.messaging.simp.annotation.SubscribeMapping;

import org.springframework.stereotype.Controller;

import java.security.Principal;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Controller
public class WebSocketApprovalHandler {
    
    private final ObjectMapper objectMapper;
    private final UnifiedApprovalService unifiedApprovalService;
    private final Map<String, String> activeUserSessions = new ConcurrentHashMap<>();
    private final SimpMessagingTemplate brokerTemplate;

    public WebSocketApprovalHandler(ObjectMapper objectMapper,
                                    UnifiedApprovalService unifiedApprovalService,
                                    @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        this.objectMapper = objectMapper;
        this.unifiedApprovalService = unifiedApprovalService;
        this.brokerTemplate = brokerTemplate;
    }

    @PostConstruct
    public void init() {
                                    }

    private static final String TOPIC_APPROVALS = "/topic/soar/approvals";
    private static final String TOPIC_APPROVAL_RESULT = "/topic/soar/approval-results/";
    private static final String QUEUE_USER_APPROVALS = "/queue/approvals";

    @SubscribeMapping("/soar/approvals")
    public Map<String, Object> subscribeToApprovals(Principal principal) {
        String userId = principal != null ? principal.getName() : "anonymous-" + System.currentTimeMillis();
        String sessionId = "session-" + System.currentTimeMillis();

        if (activeUserSessions.size() >= 10000) {
            log.error("Active session count exceeded limit ({}), clearing stale sessions", activeUserSessions.size());
            activeUserSessions.clear();
        }
        activeUserSessions.put(sessionId, userId);

        Map<String, Object> response = new HashMap<>();
        response.put("type", "SUBSCRIPTION_CONFIRMED");
        response.put("userId", userId);
        response.put("sessionId", sessionId);
        response.put("timestamp", LocalDateTime.now().toString());
        response.put("message", "Successfully subscribed to approval notifications");
        response.put("activeSessionCount", activeUserSessions.size());

        return response;
    }

    @MessageMapping("/heartbeat")
    public void handleHeartbeat(@Payload Map<String, Object> payload) {
        
            }

    @SubscribeMapping("/soar/approval-results/{approvalId}")
    public Map<String, Object> subscribeToApprovalResult(
            @DestinationVariable String approvalId,
            Principal principal) {
        
        String userId = principal != null ? principal.getName() : "anonymous";

        boolean isPending = unifiedApprovalService.isPending(approvalId);
        
        return Map.of(
            "type", "SUBSCRIPTION_CONFIRMED",
            "approvalId", approvalId,
            "isPending", isPending,
            "userId", userId,
            "timestamp", LocalDateTime.now()
        );
    }

    @MessageMapping("/soar/approve/{approvalId}")
    @SendTo("/topic/soar/approval-results/{approvalId}")
    public Map<String, Object> handleApprovalResponse(
            @DestinationVariable String approvalId,
            @Payload Map<String, Object> payload,
            Principal principal) {

        if (principal == null) {
            log.error("Unauthenticated WebSocket approval attempt rejected");
            throw new SecurityException("Authentication required for approval operations");
        }
        String reviewer = principal.getName();
        boolean approved = (boolean) payload.getOrDefault("approved", false);
        String comment = (String) payload.getOrDefault("comment", "");

        try {
            
            if (unifiedApprovalService != null) {
                unifiedApprovalService.processApprovalResponse(approvalId, approved, reviewer, comment);
                            } else {
                
                log.error("UnifiedApprovalService is null, cannot process approval");
                throw new IllegalStateException("UnifiedApprovalService not available");
            }

            Map<String, Object> response = new HashMap<>();
            response.put("type", "APPROVAL_PROCESSED");
            response.put("approvalId", approvalId);
            response.put("approved", approved);
            response.put("reviewer", reviewer);
            response.put("comment", comment);
            response.put("timestamp", LocalDateTime.now());
            response.put("success", true);

            broadcastApprovalResult(approvalId, response);
            
            return response;
            
        } catch (Exception e) {
            log.error("Approval processing failed: {}", approvalId, e);
            
            return Map.of(
                "type", "APPROVAL_ERROR",
                "approvalId", approvalId,
                "error", e.getMessage(),
                "timestamp", LocalDateTime.now(),
                "success", false
            );
        }
    }

    @MessageMapping("/soar/cancel/{approvalId}")
    @SendTo("/topic/soar/approval-results/{approvalId}")
    public Map<String, Object> handleApprovalCancellation(
            @DestinationVariable String approvalId,
            @Payload Map<String, Object> payload,
            Principal principal) {
        
        if (principal == null) {
            log.error("Unauthenticated WebSocket cancellation attempt rejected");
            throw new SecurityException("Authentication required for approval operations");
        }
        String cancelledBy = principal.getName();
        String reason = (String) payload.getOrDefault("reason", "User cancelled");

        try {
            
            unifiedApprovalService.cancelApproval(approvalId, reason);
            
            Map<String, Object> response = Map.of(
                "type", "APPROVAL_CANCELLED",
                "approvalId", approvalId,
                "cancelledBy", cancelledBy,
                "reason", reason,
                "timestamp", LocalDateTime.now(),
                "success", true
            );

            broadcastApprovalResult(approvalId, response);
            
            return response;
            
        } catch (Exception e) {
            log.error("Approval cancellation failed: {}", approvalId, e);
            
            return Map.of(
                "type", "CANCELLATION_ERROR",
                "approvalId", approvalId,
                "error", e.getMessage(),
                "timestamp", LocalDateTime.now(),
                "success", false
            );
        }
    }

    @MessageMapping("/soar/status/{approvalId}")
    @SendToUser("/queue/approval-status")
    public Map<String, Object> getApprovalStatus(
            @DestinationVariable String approvalId,
            Principal principal) {

        boolean isPending = unifiedApprovalService.isPending(approvalId);
        boolean isCompleted = unifiedApprovalService.isCompleted(approvalId);
        boolean isCancelled = unifiedApprovalService.isCancelled(approvalId);
        
        String status;
        if (isPending) {
            status = "PENDING";
        } else if (isCompleted) {
            status = "COMPLETED";
        } else if (isCancelled) {
            status = "CANCELLED";
        } else {
            status = "UNKNOWN";
        }
        
        return Map.of(
            "type", "APPROVAL_STATUS",
            "approvalId", approvalId,
            "status", status,
            "isPending", isPending,
            "isCompleted", isCompleted,
            "isCancelled", isCancelled,
            "timestamp", LocalDateTime.now()
        );
    }

    @MessageMapping("/soar/pending")
    @SendToUser("/queue/pending-approvals")
    public Map<String, Object> getPendingApprovals(Principal principal) {
        String userId = principal != null ? principal.getName() : "anonymous";
                
        return Map.of(
            "type", "PENDING_APPROVALS",
            "approvalIds", unifiedApprovalService.getPendingApprovalIds(),
            "count", unifiedApprovalService.getPendingCount(),
            "userId", userId,
            "timestamp", LocalDateTime.now()
        );
    }

    @MessageMapping("/soar/stats")
    @SendToUser("/queue/approval-stats")
    public Map<String, Object> getApprovalStatistics(Principal principal) {
                
        Map<String, Object> stats = unifiedApprovalService.getStatistics();
        stats.put("type", "APPROVAL_STATISTICS");
        stats.put("timestamp", LocalDateTime.now());
        
        return stats;
    }

    public void sendApprovalRequest(ApprovalRequest request) {
        try {
            if (brokerTemplate == null) {
                log.error("SimpMessagingTemplate is null, check WebSocket configuration");
                return;
            }

            Map<String, Object> message = new HashMap<>();
            message.put("type", "APPROVAL_REQUEST");
            message.put("approvalId", request.getRequestId());
            message.put("requestId", request.getRequestId()); 
            message.put("toolName", request.getToolName());
            message.put("description", request.getActionDescription() != null ? 
                       request.getActionDescription() : request.getToolDescription());
            message.put("riskLevel", request.getRiskLevel().name());
            message.put("requestedBy", request.getRequestedBy());
            message.put("timestamp", LocalDateTime.now().toString());
            message.put("parameters", request.getParameters());
            message.put("sessionId", request.getSessionId());
            
            message.put("messageId", request.getRequestId() + "_" + System.currentTimeMillis());

            if (activeUserSessions.isEmpty()) {
                log.error("No active WebSocket sessions, verify client connections");
            }

            try {
                brokerTemplate.convertAndSend(TOPIC_APPROVALS, (Object) message);
                                            } catch (Exception ex) {
                log.error("{} topic send failed: {}", TOPIC_APPROVALS, ex.getMessage(), ex);
            }

        } catch (Exception e) {
            log.error("WebSocket approval request send failed: {}", request.getRequestId(), e);
        }
    }

    public void broadcastTimeoutNotification(String approvalId, Map<String, Object> timeoutData) {
        try {
            
            Map<String, Object> message = new HashMap<>(timeoutData);
            message.put("messageId", approvalId + "_timeout_" + System.currentTimeMillis());

            brokerTemplate.convertAndSend(TOPIC_APPROVAL_RESULT + approvalId, (Object) message);

        } catch (Exception e) {
            log.error("Timeout notification broadcast failed", e);
        }
    }

    private void broadcastApprovalResult(String approvalId, Map<String, Object> result) {
        try {
            
            Map<String, Object> message = new HashMap<>(result);
            message.put("messageId", approvalId + "_result_" + System.currentTimeMillis());

            brokerTemplate.convertAndSend(
                TOPIC_APPROVAL_RESULT + approvalId,
                (Object) message
            );

        } catch (Exception e) {
            log.error("Approval result broadcast failed", e);
        }
    }

    public void sendTimeoutNotification(String approvalId, long timeoutSeconds) {
        Map<String, Object> message = Map.of(
            "type", "APPROVAL_TIMEOUT",
            "approvalId", approvalId,
            "timeoutSeconds", timeoutSeconds,
            "timestamp", LocalDateTime.now()
        );
        
        brokerTemplate.convertAndSend(
            TOPIC_APPROVAL_RESULT + approvalId,
            (Object) message
        );

        log.error("WebSocket timeout notification: {} ({}s)", approvalId, timeoutSeconds);
    }

    public void sendErrorNotification(String approvalId, String error) {
        Map<String, Object> message = Map.of(
            "type", "APPROVAL_ERROR",
            "approvalId", approvalId,
            "error", error,
            "timestamp", LocalDateTime.now()
        );
        
        brokerTemplate.convertAndSend(TOPIC_APPROVAL_RESULT + approvalId, (Object) message);

        log.error("WebSocket error notification: {} - {}", approvalId, error);
    }

    public void broadcastMessage(String topic, Map<String, Object> data) {
        try {
            brokerTemplate.convertAndSend(topic, (Object) data);
                    } catch (Exception e) {
            log.error("WebSocket message broadcast failed: {}", topic, e);
        }
    }

    public void sendHeartbeat() {
        Map<String, Object> heartbeatMessage = Map.of(
            "type", "HEARTBEAT",
            "message", "WebSocket connection alive",
            "timestamp", LocalDateTime.now(),
            "activeSessions", activeUserSessions.size()
        );
        
        try {
            
            brokerTemplate.convertAndSend(TOPIC_APPROVALS, (Object) heartbeatMessage);
                        
        } catch (Exception e) {
            log.error("WebSocket heartbeat send failed", e);
        }
    }

    public void registerUserSession(String sessionId, String userId) {
        activeUserSessions.put(sessionId, userId);
            }

    public void removeUserSession(String sessionId) {
        String userId = activeUserSessions.remove(sessionId);
        if (userId != null) {
                    }
    }

    public int getActiveSessionCount() {
        return activeUserSessions.size();
    }

    public void sendTestBroadcast(String message) {
        if (brokerTemplate == null) {
            log.error("TEST: SimpMessagingTemplate is null");
            return;
        }
        
        Map<String, Object> testMessage = new HashMap<>();
        testMessage.put("type", "TEST_BROADCAST");
        testMessage.put("message", message);
        testMessage.put("timestamp", LocalDateTime.now().toString());
        testMessage.put("activeSessions", activeUserSessions.size());

        try {
            brokerTemplate.convertAndSend("/topic/test", (Object) testMessage);
                    } catch (Exception e) {
            log.error("TEST: /topic/test send failed", e);
        }

        try {
            brokerTemplate.convertAndSend("/topic/soar/approvals", (Object) testMessage);
                    } catch (Exception e) {
            log.error("TEST: /topic/soar/approvals send failed", e);
        }
    }
}