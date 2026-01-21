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
import org.springframework.scheduling.annotation.Scheduled;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
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
    private final Map<String, ScheduledTimeoutTask> timeoutTasks = new ConcurrentHashMap<>();

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
            log.error("SSE 오류: {}", clientId, error);
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
            "APPROVAL_REQUEST",
            "Approval required for high-risk tool execution",
            data
        );

        if (webSocketHandler != null) {
            try {
                webSocketHandler.sendApprovalRequest(request);
                            } catch (Exception e) {
                log.error("WebSocket 승인 요청 전송 실패, SSE로 폴백: {}", request.getRequestId(), e);
                
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
        log.warn("승인 타임아웃: {}", approvalId);
        
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
                log.error("WebSocket 타임아웃 알림 전송 실패, SSE로 폴백: {}", approvalId, e);
                
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
        log.error("💥 Tool 실행 실패: {}", toolName, exception);
        
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
                log.error("SSE 전송 실패: {}", clientId, e);
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
                log.error("WebSocket 브로드캐스트 실패: {}", message.type, e);
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
        ScheduledTimeoutTask task = new ScheduledTimeoutTask(approvalId);
        timeoutTasks.put(approvalId, task);
        
        scheduler.schedule(() -> {
            if (timeoutTasks.containsKey(approvalId)) {
                sendApprovalTimeout(approvalId);
                timeoutTasks.remove(approvalId);
            }
        }, delayMillis, TimeUnit.MILLISECONDS);
    }

    private void cancelTimeout(String approvalId) {
        ScheduledTimeoutTask task = timeoutTasks.remove(approvalId);
        if (task != null) {
            task.cancel();
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
                .title("고위험 도구 실행 승인 요청")
                .message(String.format(
                    "도구 '%s' 실행에 승인이 필요합니다.\n위험도: %s\n요청자: %s",
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
            log.error("비동기 승인 요청 알림 저장 실패: {}", request.getRequestId(), e);
            
            sendApprovalRequest(request);
        }
    }

    @Async
    public void sendAsyncApprovalResult(String requestId, boolean approved, String approvedBy) {
                
        try {
            ApprovalNotification notification = ApprovalNotification.builder()
                .requestId(requestId)
                .notificationType(approved ? "APPROVAL_GRANTED" : "APPROVAL_DENIED")
                .title(approved ? "도구 실행 승인됨" : "도구 실행 거부됨")
                .message(String.format(
                    "요청 ID %s의 도구 실행이 %s되었습니다.\n처리자: %s",
                    requestId,
                    approved ? "승인" : "거부",
                    approvedBy
                ))
                .userId(approvedBy)
                .priority("HIGH")
                .actionRequired(false)
                .build();
            
            notificationRepository.save(notification);

        } catch (Exception e) {
            log.error("비동기 승인 결과 알림 저장 실패: {}", requestId, e);
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

    private static class ScheduledTimeoutTask {
        private final String approvalId;
        private volatile boolean cancelled = false;
        
        ScheduledTimeoutTask(String approvalId) {
            this.approvalId = approvalId;
        }
        
        void cancel() {
            this.cancelled = true;
        }
        
        boolean isCancelled() {
            return cancelled;
        }
    }

    public void sendApprovalReminder(String approvalId) {

        eventPublisher.publishEvent(new ApprovalReminderRequestedEvent(approvalId));
    }

    public record ApprovalReminderRequestedEvent(
        String approvalId
    ) {}
}