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

/**
 * MCP Approval Notification Service
 * 
 * MCP notifications 프로토콜을 구현하여
 * 승인 요청과 결과를 실시간으로 전송합니다.
 * WebSocket과 SSE를 모두 지원하는 통합 알림 서비스입니다.
 */
@Slf4j
@RequiredArgsConstructor
public class McpApprovalNotificationService {
    
    private final ApplicationEventPublisher eventPublisher;
    private final ObjectMapper objectMapper;
    
    // 비동기 모드를 위한 DB 저장 지원
    private final ApprovalNotificationRepository notificationRepository;
    
    // WebSocket 핸들러 주입 (옵셔널, Lazy로 순환 참조 해결)
    @Lazy
    @Autowired(required = false)
    private WebSocketApprovalHandler webSocketHandler;
    
    // Heartbeat 관련
    private final AtomicLong heartbeatCounter = new AtomicLong(0);
    
    // SSE 연결 관리
    private final Map<String, SseEmitter> sseEmitters = new ConcurrentHashMap<>();
    private final List<SseEmitter> broadcastEmitters = new CopyOnWriteArrayList<>();
    
    // 타임아웃 관리
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
    private final Map<String, ScheduledTimeoutTask> timeoutTasks = new ConcurrentHashMap<>();
    
    // 알림 히스토리
    private final List<NotificationHistory> notificationHistory = new CopyOnWriteArrayList<>();
    private static final int MAX_HISTORY_SIZE = 100;
    
    /**
     * SSE Emitter 등록
     * 타임아웃을 10분으로 설정하고 Heartbeat로 연결 유지
     */
    public SseEmitter registerEmitter(String clientId) {
        // 10분 타임아웃 (600,000ms)
        SseEmitter emitter = new SseEmitter(600000L);
        
        emitter.onCompletion(() -> {
            sseEmitters.remove(clientId);
            broadcastEmitters.remove(emitter);
            log.debug("SSE 연결 종료: {}", clientId);
        });
        
        emitter.onTimeout(() -> {
            sseEmitters.remove(clientId);
            broadcastEmitters.remove(emitter);
            log.debug("SSE 타임아웃: {}", clientId);
        });
        
        emitter.onError(error -> {
            sseEmitters.remove(clientId);
            broadcastEmitters.remove(emitter);
            log.error("SSE 오류: {}", clientId, error);
        });
        
        sseEmitters.put(clientId, emitter);
        broadcastEmitters.add(emitter);
        
        // 연결 확인 메시지 전송
        sendToClient(clientId, new NotificationMessage(
            "CONNECTION",
            "Connected to approval notification service",
            Map.of("clientId", clientId, "timestamp", LocalDateTime.now())
        ));
        
        log.info("SSE 클라이언트 등록: {}", clientId);
        return emitter;
    }
    
    /**
     * 승인 요청 이벤트 리스너
     * ApprovalEvent.APPROVAL_REQUESTED 이벤트를 처리하여 알림 전송
     */
    @EventListener
    @Async
    public void handleApprovalRequested(ApprovalEvent event) {
        if (event.getEventType() == ApprovalEvent.EventType.APPROVAL_REQUESTED) {
            sendApprovalRequest(event.getApprovalRequest());
        }
    }
    
    /**
     * 승인 허가 이벤트 리스너
     */
    @EventListener
    @Async
    public void handleApprovalGranted(ApprovalEvent event) {
        if (event.getEventType() == ApprovalEvent.EventType.APPROVAL_GRANTED) {
            sendApprovalGranted(event.getRequestId());
        }
    }
    
    /**
     * 승인 거부 이벤트 리스너
     */
    @EventListener
    @Async
    public void handleApprovalDenied(ApprovalEvent event) {
        if (event.getEventType() == ApprovalEvent.EventType.APPROVAL_DENIED) {
            sendApprovalDenied(event.getRequestId());
        }
    }
    
    /**
     * 타임아웃 이벤트 리스너
     */
    @EventListener
    @Async
    public void handleApprovalTimeout(ApprovalEvent event) {
        if (event.getEventType() == ApprovalEvent.EventType.APPROVAL_TIMEOUT) {
            sendApprovalTimeout(event.getRequestId());
        }
    }
    
    /**
     * 도구 실행 완료 이벤트 리스너
     */
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
    
    /**
     * 도구 실행 실패 이벤트 리스너
     */
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
    
    /**
     * 승인 요청 알림 전송
     * WebSocket을 우선 사용하고, WebSocket이 없을 때만 SSE 사용
     * 기존 코드 호환성을 위해 public 유지
     */
    @Async
    public void sendApprovalRequest(ApprovalRequest request) {
        log.info("승인 요청 알림 전송: {}", request.getRequestId());
        
        // Map.of()는 null을 허용하지 않으므로 HashMap 사용
        Map<String, Object> data = buildNotificationData(request);
        
        NotificationMessage notification = new NotificationMessage(
            "APPROVAL_REQUEST",
            "Approval required for high-risk tool execution",
            data
        );
        
        // WebSocket이 활성화되어 있으면 WebSocket만 사용
        if (webSocketHandler != null) {
            try {
                webSocketHandler.sendApprovalRequest(request);
                log.debug("WebSocket 승인 요청 전송 완료: {}", request.getRequestId());
            } catch (Exception e) {
                log.error("WebSocket 승인 요청 전송 실패, SSE로 폴백: {}", request.getRequestId(), e);
                // WebSocket 실패 시 SSE로 폴백
                broadcast(notification);
            }
        } else {
            // WebSocket이 없을 때만 SSE 사용
            log.debug("WebSocket 핸들러 없음, SSE로 전송: {}", request.getRequestId());
            broadcast(notification);
        }
        
        // 이벤트 발행
        eventPublisher.publishEvent(new ApprovalRequestEvent(request));
        
        // 타임아웃 설정
        String riskLevelName = request.getRiskLevel() != null ? 
            request.getRiskLevel().name() : "MEDIUM";
        scheduleTimeout(request.getRequestId(), getTimeoutDuration(riskLevelName));
        
        // 히스토리 저장
        addToHistory(notification);
    }
    
    /**
     * 승인 허가 알림
     * 기존 코드 호환성을 위해 public 유지
     */
    @Async
    public void sendApprovalGranted(String approvalId) {
        log.info("승인 허가 알림: {}", approvalId);
        
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
    
    /**
     * 승인 거부 알림
     * 기존 코드 호환성을 위해 public 유지
     */
    @Async
    public void sendApprovalDenied(String approvalId) {
        log.info("승인 거부 알림: {}", approvalId);
        
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
    
    /**
     * 승인 타임아웃 알림
     * WebSocket을 우선 사용하고, WebSocket이 없을 때만 SSE 사용
     * 기존 코드 호환성을 위해 public 유지
     */
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
        
        // WebSocket이 활성화되어 있으면 WebSocket만 사용
        if (webSocketHandler != null) {
            try {
                webSocketHandler.broadcastTimeoutNotification(approvalId, timeoutData);
                log.debug("WebSocket 타임아웃 알림 전송 완료: {}", approvalId);
            } catch (Exception e) {
                log.error("WebSocket 타임아웃 알림 전송 실패, SSE로 폴백: {}", approvalId, e);
                // WebSocket 실패 시 SSE로 폴백
                broadcast(notification);
            }
        } else {
            // WebSocket이 없을 때만 SSE 사용
            log.debug("WebSocket 핸들러 없음, SSE로 전송: {}", approvalId);
            broadcast(notification);
        }
        
        addToHistory(notification);
    }
    
    /**
     * Tool 실행 완료 알림
     * 기존 코드 호환성을 위해 public 유지
     */
    @Async
    public void sendExecutionCompleted(String toolName, Object result, long executionTime) {
        log.info("Tool 실행 완료: {} ({}ms)", toolName, executionTime);
        
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
    
    /**
     * 알림 데이터 생성 (null 안전 처리)
     */
    private Map<String, Object> buildNotificationData(ApprovalRequest request) {
        Map<String, Object> data = new HashMap<>();
        
        // 필수 필드들 null 체크하여 추가
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
        
        // description 처리: toolDescription > actionDescription > 기본값
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
    
    /**
     * Tool 실행 실패 알림
     * 기존 코드 호환성을 위해 public 유지
     */
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
    
    /**
     * Tool 호출 감지 알림
     */
    @Async
    public void sendToolCallDetected(List<String> toolNames) {
        log.info("📞 Tool 호출 감지: {}", String.join(", ", toolNames));
        
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
    
    /**
     * 특정 클라이언트에게 메시지 전송
     */
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
    
    /**
     * UnifiedNotificationService에서 사용하는 브로드캐스트 메서드
     */
    public void broadcastMessage(Map<String, Object> messageData) {
        NotificationMessage message = new NotificationMessage(
            "notification",
            "WebSocket broadcast message",
            messageData
        );
        broadcast(message);
    }
    
    /**
     * 모든 클라이언트에게 브로드캐스트
     */
    private void broadcast(NotificationMessage message) {
        // 1. SSE로 브로드캐스트
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
        
        // 실패한 emitter 제거
        broadcastEmitters.removeAll(deadEmitters);
        
        // 2. WebSocket으로도 브로드캐스트 (타입별 토픽 매핑)
        if (webSocketHandler != null) {
            try {
                String topic = mapMessageTypeToTopic(message.type);
                if (topic != null) {
                    webSocketHandler.broadcastMessage(topic, message.data);
                    log.debug("WebSocket 브로드캐스트: {} -> {}", message.type, topic);
                }
            } catch (Exception e) {
                log.error("WebSocket 브로드캐스트 실패: {}", message.type, e);
            }
        }
    }
    
    /**
     * 메시지 타입을 WebSocket 토픽으로 매핑
     */
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
    
    /**
     * 타임아웃 스케줄링
     */
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
    
    /**
     * 타임아웃 취소
     */
    private void cancelTimeout(String approvalId) {
        ScheduledTimeoutTask task = timeoutTasks.remove(approvalId);
        if (task != null) {
            task.cancel();
        }
    }
    
    /**
     * 위험도에 따른 타임아웃 시간 결정
     */
    private long getTimeoutDuration(String riskLevel) {
        return switch (riskLevel) {
            case "CRITICAL" -> 120000; // 2분
            case "HIGH" -> 300000;     // 5분
            case "MEDIUM" -> 600000;   // 10분
            default -> 900000;         // 15분
        };
    }
    
    /**
     * 결과 요약
     */
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
    
    /**
     * 히스토리 추가
     */
    private void addToHistory(NotificationMessage notification) {
        notificationHistory.add(new NotificationHistory(
            notification,
            LocalDateTime.now()
        ));
        
        // 최대 크기 유지
        while (notificationHistory.size() > MAX_HISTORY_SIZE) {
            notificationHistory.remove(0);
        }
    }
    
    /**
     * 히스토리 조회
     */
    public List<NotificationHistory> getHistory(int limit) {
        int size = notificationHistory.size();
        int fromIndex = Math.max(0, size - limit);
        return new ArrayList<>(notificationHistory.subList(fromIndex, size));
    }
    
    /**
     * 알림 메시지 클래스
     */
    private record NotificationMessage(
        String type,
        String message,
        Map<String, Object> data
    ) {}
    
    /**
     * 알림 히스토리 클래스
     */
    public record NotificationHistory(
        NotificationMessage notification,
        LocalDateTime timestamp
    ) {}
    
    /**
     * 승인 요청 이벤트
     */
    public record ApprovalRequestEvent(
        ApprovalRequest request
    ) {}
    
    /**
     * 비동기 승인 요청 알림 전송 (DB 저장)
     * Agent 모드에서 사용 - 실시간 WebSocket/SSE 대신 DB에 저장
     */
    @Async
    public void sendAsyncApprovalRequest(ApprovalRequest request, ToolExecutionContext executionContext) {
        log.info("비동기 승인 요청 알림 저장: {}", request.getRequestId());
        
        try {
            // 알림 엔티티 생성 및 저장
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
                .targetRole("SECURITY_ADMIN") // 보안 관리자 역할
                .priority(mapRiskToPriority(request.getRiskLevel()))
                .actionRequired(true)
                .groupId(executionContext.getIncidentId())
                .expiresAt(LocalDateTime.now().plusMinutes(30)) // 30분 만료
                .build();
            
            // 메타데이터 설정
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("toolName", request.getToolName());
            metadata.put("riskLevel", request.getRiskLevel() != null ? request.getRiskLevel().toString() : "UNKNOWN");
            metadata.put("executionContextId", executionContext.getId());
            metadata.put("sessionId", executionContext.getSessionId());
            notification.setNotificationData(metadata);
            
            // DB에 저장
            notificationRepository.save(notification);
            
            log.info("비동기 승인 요청 알림 저장 완료: ID={}, RequestId={}", 
                notification.getId(), request.getRequestId());
            
            // 이벤트 발행 (다른 서비스에서 처리 가능)
            eventPublisher.publishEvent(new AsyncApprovalRequestEvent(request, notification, executionContext));
            
        } catch (Exception e) {
            log.error("비동기 승인 요청 알림 저장 실패: {}", request.getRequestId(), e);
            // 실패 시 동기 모드로 폴백 시도 (가능한 경우)
            sendApprovalRequest(request);
        }
    }
    
    /**
     * 비동기 승인 결과 알림 저장
     */
    @Async
    public void sendAsyncApprovalResult(String requestId, boolean approved, String approvedBy) {
        log.info("비동기 승인 결과 알림 저장: {} - {}", requestId, approved ? "승인" : "거부");
        
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
            
            log.info("비동기 승인 결과 알림 저장 완료: {}", requestId);
            
        } catch (Exception e) {
            log.error("비동기 승인 결과 알림 저장 실패: {}", requestId, e);
        }
    }
    
    /**
     * 위험도를 우선순위로 매핑
     */
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
    
    /**
     * 비동기 승인 요청 이벤트
     */
    public record AsyncApprovalRequestEvent(
        ApprovalRequest request,
        ApprovalNotification notification,
        ToolExecutionContext executionContext
    ) {}
    
    /**
     * SSE Heartbeat 전송
     * 30초마다 실행되어 연결을 유지합니다.
     */
//    @Scheduled(fixedDelay = 30000, initialDelay = 30000)
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
        
        // SSE Heartbeat 전송
        List<String> deadClients = new ArrayList<>();
        sseEmitters.forEach((clientId, emitter) -> {
            try {
                emitter.send(SseEmitter.event()
                    .name("heartbeat")
                    .data(heartbeat));
                log.trace("💓 SSE Heartbeat 전송: {} (#{}))", clientId, count);
            } catch (IOException e) {
                log.debug("SSE Heartbeat 실패 - 연결 제거: {}", clientId);
                deadClients.add(clientId);
            }
        });
        
        // 죽은 연결 제거
        deadClients.forEach(clientId -> {
            sseEmitters.remove(clientId);
            log.debug("SSE 연결 제거: {}", clientId);
        });
        
        // WebSocket Heartbeat도 전송
        if (webSocketHandler != null) {
            try {
                webSocketHandler.sendHeartbeat();
                log.trace("💓 WebSocket Heartbeat 전송 (#{}))", count);
            } catch (Exception e) {
                log.debug("WebSocket Heartbeat 실패: {}", e.getMessage());
            }
        }
        
        if (count % 10 == 0) {
            log.info("💓 Heartbeat #{}: SSE 연결 {}, WebSocket {}", 
                count, sseEmitters.size(), 
                webSocketHandler != null ? "활성" : "비활성");
        }
    }
    
    /**
     * 타임아웃 태스크
     */
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
    
    /**
     * Send approval reminder
     * 이제는 이벤트를 통해 간접적으로 처리됨
     */
    public void sendApprovalReminder(String approvalId) {
        // approvalService 직접 호출 대신 이벤트 발행
        log.info("Approval reminder requested for: {}", approvalId);
        // UnifiedApprovalService가 이벤트를 발행하도록 위임
        eventPublisher.publishEvent(new ApprovalReminderRequestedEvent(approvalId));
    }
    
    /**
     * 승인 알림 이벤트 (내부용)
     */
    public record ApprovalReminderRequestedEvent(
        String approvalId
    ) {}
}