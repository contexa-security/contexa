package io.contexa.contexacoreenterprise.soar.approval;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.entity.ApprovalNotification;
import io.contexa.contexacoreenterprise.domain.entity.ToolExecutionContext;
import io.contexa.contexacore.repository.ApprovalNotificationRepository;
import io.contexa.contexacoreenterprise.soar.event.ApprovalEvent;
import org.springframework.context.event.EventListener;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import io.contexa.contexacoreenterprise.soar.event.WebSocketApprovalHandler;
import jakarta.annotation.PreDestroy;
import org.springframework.scheduling.annotation.Scheduled;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@RequiredArgsConstructor
public class McpApprovalNotificationService {
    
    private final ApplicationEventPublisher eventPublisher;
    private final ObjectMapper objectMapper;

    private final ApprovalNotificationRepository notificationRepository;

    @Lazy
    @Autowired(required = false)
    private WebSocketApprovalHandler webSocketHandler;

    private final AtomicLong heartbeatCounter = new AtomicLong(0);

    private final Map<String, SseEmitter> sseEmitters = new ConcurrentHashMap<>();
    private final List<SseEmitter> broadcastEmitters = new CopyOnWriteArrayList<>();

    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
    private final Map<String, ScheduledFuture<?>> timeoutFutures = new ConcurrentHashMap<>();

    private final List<NotificationHistory> notificationHistory = new CopyOnWriteArrayList<>();
    private static final int MAX_HISTORY_SIZE = 100;

    public SseEmitter registerEmitter(String clientId) {
        
        SseEmitter emitter = new SseEmitter(600000L);
        
        emitter.onCompletion(() -> {
            sseEmitters.remove(clientId);
            broadcastEmitters.remove(emitter);
                    });
        
        emitter.onTimeout(() -> {
            sseEmitters.remove(clientId);
            broadcastEmitters.remove(emitter);
                    });
        
        emitter.onError(error -> {
            sseEmitters.remove(clientId);
            broadcastEmitters.remove(emitter);
            log.error("SSE error: {}", clientId, error);
        });
        
        sseEmitters.put(clientId, emitter);
        broadcastEmitters.add(emitter);

        sendToClient(clientId, new NotificationMessage(
            "CONNECTION",
            "Connected to approval notification service",
            Map.of("clientId", clientId, "timestamp", LocalDateTime.now())
        ));
        
                return emitter;
    }

    @EventListener
    @Async
    public void handleApprovalRequested(ApprovalEvent event) {
        if (event.getEventType() == ApprovalEvent.EventType.APPROVAL_REQUESTED) {
            sendApprovalRequest(event.getApprovalRequest());
        }
    }

    @EventListener
    @Async
    public void handleApprovalGranted(ApprovalEvent event) {
        if (event.getEventType() == ApprovalEvent.EventType.APPROVAL_GRANTED) {
            sendApprovalGranted(event.getRequestId());
        }
    }

    @EventListener
    @Async
    public void handleApprovalDenied(ApprovalEvent event) {
        if (event.getEventType() == ApprovalEvent.EventType.APPROVAL_DENIED) {
            sendApprovalDenied(event.getRequestId());
        }
    }

    @EventListener
    @Async
    public void handleApprovalTimeout(ApprovalEvent event) {
        if (event.getEventType() == ApprovalEvent.EventType.APPROVAL_TIMEOUT) {
            sendApprovalTimeout(event.getRequestId());
        }
    }

    @EventListener
    @Async
    public void handleToolExecuted(ApprovalEvent event) {
        if (event.getEventType() == ApprovalEvent.EventType.TOOL_EXECUTED) {
            Map<String, Object> metadata = event.getMetadata();
            if (metadata != null) {
                String toolName = (String) metadata.get("toolName");
                Object result = metadata.get("result");
                Long executionTime = (Long) metadata.get("executionTime");
                if (toolName != null && executionTime != null) {
                    sendExecutionCompleted(toolName, result, executionTime);
                }
            }
        }
    }

    @EventListener
    @Async
    public void handleToolFailed(ApprovalEvent event) {
        if (event.getEventType() == ApprovalEvent.EventType.TOOL_FAILED) {
            Map<String, Object> metadata = event.getMetadata();
            if (metadata != null) {
                String toolName = (String) metadata.get("toolName");
                String error = (String) metadata.get("error");
                if (toolName != null && error != null) {
                    sendExecutionFailed(toolName, new RuntimeException(error));
                }
            }
        }
    }

    @Async
    public void sendApprovalRequest(ApprovalRequest request) {

        Map<String, Object> data = buildNotificationData(request);
        
        NotificationMessage notification = new NotificationMessage(
            "APPROVAL_REQUESTED",
            "Approval required for high-risk tool execution",
            data
        );

        if (webSocketHandler != null) {
            try {
                webSocketHandler.sendApprovalRequest(request);
                            } catch (Exception e) {
                log.error("WebSocket approval request send failed, falling back to SSE: {}", request.getRequestId(), e);
                
                broadcast(notification);
            }
        } else {
            
                        broadcast(notification);
        }

        eventPublisher.publishEvent(new ApprovalRequestEvent(request));

        String riskLevelName = request.getRiskLevel() != null ? 
            request.getRiskLevel().name() : "MEDIUM";
        scheduleTimeout(request.getRequestId(), getTimeoutDuration(riskLevelName));

        addToHistory(notification);
    }

    @Async
    public void sendApprovalGranted(String approvalId) {
                
        NotificationMessage notification = new NotificationMessage(
            "APPROVAL_GRANTED",
            "Tool execution approved",
            Map.of(
                "approvalId", approvalId,
                "timestamp", LocalDateTime.now(),
                "status", "APPROVED"
            )
        );
        
        broadcast(notification);
        cancelTimeout(approvalId);
        addToHistory(notification);
    }

    @Async
    public void sendApprovalDenied(String approvalId) {
                
        NotificationMessage notification = new NotificationMessage(
            "APPROVAL_DENIED",
            "Tool execution denied",
            Map.of(
                "approvalId", approvalId,
                "timestamp", LocalDateTime.now(),
                "status", "DENIED"
            )
        );
        
        broadcast(notification);
        cancelTimeout(approvalId);
        addToHistory(notification);
    }

    @Async
    public void sendApprovalTimeout(String approvalId) {
        log.error("Approval timeout: {}", approvalId);
        
        Map<String, Object> timeoutData = Map.of(
            "approvalId", approvalId,
            "timestamp", LocalDateTime.now(),
            "status", "TIMEOUT",
            "type", "APPROVAL_TIMEOUT"
        );
        
        NotificationMessage notification = new NotificationMessage(
            "APPROVAL_TIMEOUT",
            "Approval request timed out",
            timeoutData
        );

        if (webSocketHandler != null) {
            try {
                webSocketHandler.broadcastTimeoutNotification(approvalId, timeoutData);
                            } catch (Exception e) {
                log.error("WebSocket timeout notification send failed, falling back to SSE: {}", approvalId, e);
                
                broadcast(notification);
            }
        } else {
            
                        broadcast(notification);
        }
        
        addToHistory(notification);
    }

    @Async
    public void sendExecutionCompleted(String toolName, Object result, long executionTime) {
                
        NotificationMessage notification = new NotificationMessage(
            "EXECUTION_COMPLETED",
            "Tool execution completed successfully",
            Map.of(
                "toolName", toolName,
                "executionTime", executionTime,
                "timestamp", LocalDateTime.now(),
                "resultSummary", summarizeResult(result)
            )
        );
        
        broadcast(notification);
        addToHistory(notification);
    }

    private Map<String, Object> buildNotificationData(ApprovalRequest request) {
        Map<String, Object> data = new HashMap<>();

        if (request.getRequestId() != null) {
            data.put("requestId", request.getRequestId());
        }
        
        if (request.getToolName() != null) {
            data.put("toolName", request.getToolName());
        }
        
        if (request.getRiskLevel() != null) {
            data.put("riskLevel", request.getRiskLevel().toString());
        }
        
        if (request.getRequestedAt() != null) {
            data.put("requestTime", request.getRequestedAt());
        } else {
            data.put("requestTime", LocalDateTime.now());
        }
        
        if (request.getRequestedBy() != null) {
            data.put("requester", request.getRequestedBy());
        }

        String description = request.getToolDescription();
        if (description == null) {
            description = request.getActionDescription();
        }
        if (description != null) {
            data.put("description", description);
        }
        
        if (request.getParameters() != null) {
            data.put("parameters", request.getParameters());
        } else {
            data.put("parameters", new HashMap<>());
        }
        
        return data;
    }

    @Async
    public void sendExecutionFailed(String toolName, Exception exception) {
        log.error("Tool execution failed: {}", toolName, exception);
        
        NotificationMessage notification = new NotificationMessage(
            "EXECUTION_FAILED",
            "Tool execution failed",
            Map.of(
                "toolName", toolName,
                "error", exception.getMessage(),
                "errorType", exception.getClass().getSimpleName(),
                "timestamp", LocalDateTime.now()
            )
        );
        
        broadcast(notification);
        addToHistory(notification);
    }

    @Async
    public void sendToolCallDetected(List<String> toolNames) {
                
        NotificationMessage notification = new NotificationMessage(
            "TOOL_CALL_DETECTED",
            "Tool calls detected in chat response",
            Map.of(
                "tools", toolNames,
                "count", toolNames.size(),
                "timestamp", LocalDateTime.now()
            )
        );
        
        broadcast(notification);
        addToHistory(notification);
    }

    private void sendToClient(String clientId, NotificationMessage message) {
        SseEmitter emitter = sseEmitters.get(clientId);
        if (emitter != null) {
            try {
                emitter.send(SseEmitter.event()
                    .name(message.type)
                    .data(objectMapper.writeValueAsString(message))
                    .id(UUID.randomUUID().toString())
                    .reconnectTime(3000L));
            } catch (IOException e) {
                log.error("SSE send failed: {}", clientId, e);
                sseEmitters.remove(clientId);
                broadcastEmitters.remove(emitter);
            }
        }
    }

    public void broadcastMessage(Map<String, Object> messageData) {
        NotificationMessage message = new NotificationMessage(
            "notification",
            "WebSocket broadcast message",
            messageData
        );
        broadcast(message);
    }

    private void broadcast(NotificationMessage message) {
        
        List<SseEmitter> deadEmitters = new ArrayList<>();
        
        broadcastEmitters.forEach(emitter -> {
            try {
                emitter.send(SseEmitter.event()
                    .name(message.type)
                    .data(objectMapper.writeValueAsString(message))
                    .id(UUID.randomUUID().toString())
                    .reconnectTime(3000L));
            } catch (Exception e) {
                deadEmitters.add(emitter);
            }
        });

        broadcastEmitters.removeAll(deadEmitters);

        if (webSocketHandler != null) {
            try {
                String topic = mapMessageTypeToTopic(message.type);
                if (topic != null) {
                    webSocketHandler.broadcastMessage(topic, message.data);
                                    }
            } catch (Exception e) {
                log.error("WebSocket broadcast failed: {}", message.type, e);
            }
        }
    }

    private String mapMessageTypeToTopic(String messageType) {
        return switch (messageType) {
            case "APPROVAL_GRANTED" -> "/topic/approval/granted";
            case "APPROVAL_DENIED" -> "/topic/approval/denied";
            case "APPROVAL_TIMEOUT" -> "/topic/approval/timeout";
            case "APPROVAL_REQUESTED" -> "/topic/soar/approvals";
            case "TOOL_CALL_DETECTED" -> "/topic/tool/detected";
            case "EXECUTION_FAILED" -> "/topic/tool/failed";
            default -> null;
        };
    }

    private void scheduleTimeout(String approvalId, long delayMillis) {
        java.util.concurrent.ScheduledFuture<?> future = scheduler.schedule(() -> {
            timeoutFutures.remove(approvalId);
            sendApprovalTimeout(approvalId);
        }, delayMillis, TimeUnit.MILLISECONDS);

        java.util.concurrent.ScheduledFuture<?> previous = timeoutFutures.put(approvalId, future);
        if (previous != null) {
            previous.cancel(false);
        }
    }

    private void cancelTimeout(String approvalId) {
        java.util.concurrent.ScheduledFuture<?> future = timeoutFutures.remove(approvalId);
        if (future != null) {
            future.cancel(false);
        }
    }

    private long getTimeoutDuration(String riskLevel) {
        return switch (riskLevel) {
            case "CRITICAL" -> 120000; 
            case "HIGH" -> 300000;     
            case "MEDIUM" -> 600000;   
            default -> 900000;         
        };
    }

    private String summarizeResult(Object result) {
        if (result == null) {
            return "No result";
        }
        
        String resultStr = result.toString();
        if (resultStr.length() > 100) {
            return resultStr.substring(0, 97) + "...";
        }
        
        return resultStr;
    }

    private void addToHistory(NotificationMessage notification) {
        notificationHistory.add(new NotificationHistory(
            notification,
            LocalDateTime.now()
        ));

        while (notificationHistory.size() > MAX_HISTORY_SIZE) {
            notificationHistory.remove(0);
        }
    }

    public List<NotificationHistory> getHistory(int limit) {
        int size = notificationHistory.size();
        int fromIndex = Math.max(0, size - limit);
        return new ArrayList<>(notificationHistory.subList(fromIndex, size));
    }

    private record NotificationMessage(
        String type,
        String message,
        Map<String, Object> data
    ) {}

    public record NotificationHistory(
        NotificationMessage notification,
        LocalDateTime timestamp
    ) {}

    public record ApprovalRequestEvent(
        ApprovalRequest request
    ) {}

    @Async
    public void sendAsyncApprovalRequest(ApprovalRequest request, ToolExecutionContext executionContext) {
                
        try {
            
            ApprovalNotification notification = ApprovalNotification.builder()
                .requestId(request.getRequestId())
                .notificationType("APPROVAL_REQUEST")
                .title("High-risk tool execution approval request")
                .message(String.format(
                    "Approval required for tool '%s' execution.\nRisk level: %s\nRequested by: %s",
                    request.getToolName(),
                    request.getRiskLevel(),
                    request.getRequestedBy()
                ))
                .userId(request.getUserId())
                .targetRole("SECURITY_ADMIN") 
                .priority(mapRiskToPriority(request.getRiskLevel()))
                .actionRequired(true)
                .groupId(executionContext.getIncidentId())
                .expiresAt(LocalDateTime.now().plusMinutes(30)) 
                .build();

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("toolName", request.getToolName());
            metadata.put("riskLevel", request.getRiskLevel() != null ? request.getRiskLevel().toString() : "UNKNOWN");
            metadata.put("executionContextId", executionContext.getId());
            metadata.put("sessionId", executionContext.getSessionId());
            notification.setNotificationData(metadata);

            notificationRepository.save(notification);

            eventPublisher.publishEvent(new AsyncApprovalRequestEvent(request, notification, executionContext));
            
        } catch (Exception e) {
            log.error("Async approval request notification save failed: {}", request.getRequestId(), e);
            
            sendApprovalRequest(request);
        }
    }

    @Async
    public void sendAsyncApprovalResult(String requestId, boolean approved, String approvedBy) {
                
        try {
            ApprovalNotification notification = ApprovalNotification.builder()
                .requestId(requestId)
                .notificationType(approved ? "APPROVAL_GRANTED" : "APPROVAL_DENIED")
                .title(approved ? "Tool execution approved" : "Tool execution denied")
                .message(String.format(
                    "Tool execution for request ID %s has been %s.\nProcessed by: %s",
                    requestId,
                    approved ? "approved" : "denied",
                    approvedBy
                ))
                .userId(approvedBy)
                .priority("HIGH")
                .actionRequired(false)
                .build();
            
            notificationRepository.save(notification);

        } catch (Exception e) {
            log.error("Async approval result notification save failed: {}", requestId, e);
        }
    }

    private String mapRiskToPriority(ApprovalRequest.RiskLevel riskLevel) {
        if (riskLevel == null) {
            return "MEDIUM";
        }
        return switch (riskLevel) {
            case CRITICAL -> "CRITICAL";
            case HIGH -> "HIGH";
            case MEDIUM -> "MEDIUM";
            case LOW -> "LOW";
            default -> "INFO";
        };
    }

    public record AsyncApprovalRequestEvent(
        ApprovalRequest request,
        ApprovalNotification notification,
        ToolExecutionContext executionContext
    ) {}

    public void sendHeartbeat() {
        long count = heartbeatCounter.incrementAndGet();
        
        NotificationMessage heartbeat = new NotificationMessage(
            "HEARTBEAT",
            "Connection alive",
            Map.of(
                "timestamp", LocalDateTime.now(),
                "count", count,
                "activeConnections", sseEmitters.size()
            )
        );

        List<String> deadClients = new ArrayList<>();
        sseEmitters.forEach((clientId, emitter) -> {
            try {
                emitter.send(SseEmitter.event()
                    .name("heartbeat")
                    .data(heartbeat));
                            } catch (IOException e) {
                                deadClients.add(clientId);
            }
        });

        deadClients.forEach(clientId -> {
            sseEmitters.remove(clientId);
                    });

        if (webSocketHandler != null) {
            try {
                webSocketHandler.sendHeartbeat();
                            } catch (Exception e) {
                            }
        }
        
        if (count % 10 == 0) {
                    }
    }


    public void sendApprovalReminder(String approvalId) {

        eventPublisher.publishEvent(new ApprovalReminderRequestedEvent(approvalId));
    }

    public record ApprovalReminderRequestedEvent(
        String approvalId
    ) {}

    @PreDestroy
    public void destroy() {
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
        timeoutFutures.values().forEach(f -> f.cancel(false));
        timeoutFutures.clear();
    }
}