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

import java.security.Principal;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * WebSocket 승인 핸들러
 * 
 * STOMP 프로토콜을 사용하여 실시간 양방향 승인 처리를 제공합니다.
 * 폴링 없이 실시간으로 승인 요청과 응답을 처리합니다.
 */
@Slf4j
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
        log.info("WebSocketApprovalHandler 초기화");
        log.info("SimpMessagingTemplate: {}", brokerTemplate != null ? "정상" : "NULL");
        log.info("ObjectMapper: {}", objectMapper != null ? "정상" : "NULL");
        log.info("UnifiedApprovalService: {}", unifiedApprovalService != null ? "정상" : "NULL");
    }
    
    // 엔드포인트 상수
    private static final String TOPIC_APPROVALS = "/topic/soar/approvals";
    private static final String TOPIC_APPROVAL_RESULT = "/topic/soar/approval-results/";
    private static final String QUEUE_USER_APPROVALS = "/queue/approvals";
    
    /**
     * 승인 요청 구독
     * 클라이언트가 승인 토픽을 구독할 때 호출됩니다.
     */
    @SubscribeMapping("/soar/approvals")
    public Map<String, Object> subscribeToApprovals(Principal principal) {
        String userId = principal != null ? principal.getName() : "anonymous-" + System.currentTimeMillis();
        String sessionId = "session-" + System.currentTimeMillis();
        
        log.info("========================================");
        log.info("새로운 WebSocket 구독 요청");
        log.info("사용자: {}", userId);
        log.info("엔드포인트: /soar/approvals");
        
        // 세션 등록
        activeUserSessions.put(sessionId, userId);
        log.info("세션 등록 완료: {} -> {}", sessionId, userId);
        log.info("현재 활성 세션 수: {}", activeUserSessions.size());
        log.info("활성 세션 목록: {}", activeUserSessions);
        
        // 초기 연결 확인 메시지
        Map<String, Object> response = new HashMap<>();
        response.put("type", "SUBSCRIPTION_CONFIRMED");
        response.put("userId", userId);
        response.put("sessionId", sessionId);
        response.put("timestamp", LocalDateTime.now().toString());
        response.put("message", "Successfully subscribed to approval notifications");
        response.put("activeSessionCount", activeUserSessions.size());
        
        log.info("구독 확인 메시지 전송: {}", response);
        log.info("========================================");
        
        return response;
    }
    
    /**
     * Heartbeat 처리 - 연결 유지용
     */
    @MessageMapping("/heartbeat")
    public void handleHeartbeat(@Payload Map<String, Object> payload) {
        // 단순히 heartbeat 수신만 처리, 응답 불필요
        log.trace("💓 Heartbeat received: {}", payload.get("timestamp"));
    }
    
    /**
     * 특정 승인 ID 구독
     */
    @SubscribeMapping("/soar/approval-results/{approvalId}")
    public Map<String, Object> subscribeToApprovalResult(
            @DestinationVariable String approvalId,
            Principal principal) {
        
        String userId = principal != null ? principal.getName() : "anonymous";
        log.info("WebSocket 구독: {} -> 승인 ID: {}", userId, approvalId);
        
        // 승인 상태 확인 (UnifiedApprovalService에서 조회)
        boolean isPending = unifiedApprovalService.isPending(approvalId);
        
        return Map.of(
            "type", "SUBSCRIPTION_CONFIRMED",
            "approvalId", approvalId,
            "isPending", isPending,
            "userId", userId,
            "timestamp", LocalDateTime.now()
        );
    }
    
    /**
     * 승인 응답 처리 (클라이언트 -> 서버)
     * 
     * 사용자가 승인/거부 결정을 전송합니다.
     */
    @MessageMapping("/soar/approve/{approvalId}")
    @SendTo("/topic/soar/approval-results/{approvalId}")
    public Map<String, Object> handleApprovalResponse(
            @DestinationVariable String approvalId,
            @Payload Map<String, Object> payload,
            Principal principal) {
        
        log.info("========================================");
        log.info("승인 응답 수신 - approvalId: {}", approvalId);
        log.info("Payload 전체: {}", payload);
        log.info("========================================");
        
        String reviewer = principal != null ? principal.getName() : "WebSocket User";
        boolean approved = (boolean) payload.getOrDefault("approved", false);
        String comment = (String) payload.getOrDefault("comment", "");
        
        log.info("WebSocket 승인 응답 수신: {} - {} (검토자: {})", 
            approvalId, approved ? "APPROVED" : "REJECTED", reviewer);
        
        try {
            // UnifiedApprovalService를 통해 승인 처리
            if (unifiedApprovalService != null) {
                unifiedApprovalService.processApprovalResponse(approvalId, approved, reviewer, comment);
                log.info("UnifiedApprovalService로 승인 처리 완료: {}", approvalId);
            } else {
                // UnifiedApprovalService가 없으면 오류
                log.error("UnifiedApprovalService가 없어 승인을 처리할 수 없습니다.");
                throw new IllegalStateException("UnifiedApprovalService not available");
            }
            
            // 응답 메시지 생성 (가변 Map 사용)
            Map<String, Object> response = new HashMap<>();
            response.put("type", "APPROVAL_PROCESSED");
            response.put("approvalId", approvalId);
            response.put("approved", approved);
            response.put("reviewer", reviewer);
            response.put("comment", comment);
            response.put("timestamp", LocalDateTime.now());
            response.put("success", true);
            
            // 브로드캐스트
            broadcastApprovalResult(approvalId, response);
            
            return response;
            
        } catch (Exception e) {
            log.error("승인 처리 실패: {}", approvalId, e);
            
            return Map.of(
                "type", "APPROVAL_ERROR",
                "approvalId", approvalId,
                "error", e.getMessage(),
                "timestamp", LocalDateTime.now(),
                "success", false
            );
        }
    }
    
    /**
     * 승인 취소 처리
     */
    @MessageMapping("/soar/cancel/{approvalId}")
    @SendTo("/topic/soar/approval-results/{approvalId}")
    public Map<String, Object> handleApprovalCancellation(
            @DestinationVariable String approvalId,
            @Payload Map<String, Object> payload,
            Principal principal) {
        
        String cancelledBy = principal != null ? principal.getName() : "WebSocket User";
        String reason = (String) payload.getOrDefault("reason", "User cancelled");
        
        log.info("🚫 WebSocket 승인 취소: {} (취소자: {})", approvalId, cancelledBy);
        
        try {
            // UnifiedApprovalService를 통해 취소 처리
            unifiedApprovalService.cancelApproval(approvalId, reason);
            
            Map<String, Object> response = Map.of(
                "type", "APPROVAL_CANCELLED",
                "approvalId", approvalId,
                "cancelledBy", cancelledBy,
                "reason", reason,
                "timestamp", LocalDateTime.now(),
                "success", true
            );
            
            // 브로드캐스트
            broadcastApprovalResult(approvalId, response);
            
            return response;
            
        } catch (Exception e) {
            log.error("승인 취소 실패: {}", approvalId, e);
            
            return Map.of(
                "type", "CANCELLATION_ERROR",
                "approvalId", approvalId,
                "error", e.getMessage(),
                "timestamp", LocalDateTime.now(),
                "success", false
            );
        }
    }
    
    /**
     * 승인 상태 조회
     */
    @MessageMapping("/soar/status/{approvalId}")
    @SendToUser("/queue/approval-status")
    public Map<String, Object> getApprovalStatus(
            @DestinationVariable String approvalId,
            Principal principal) {
        
        log.debug("승인 상태 조회: {}", approvalId);
        
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
    
    /**
     * 대기 중인 승인 목록 조회
     */
    @MessageMapping("/soar/pending")
    @SendToUser("/queue/pending-approvals")
    public Map<String, Object> getPendingApprovals(Principal principal) {
        String userId = principal != null ? principal.getName() : "anonymous";
        log.debug("대기 중인 승인 목록 조회: {}", userId);
        
        return Map.of(
            "type", "PENDING_APPROVALS",
            "approvalIds", unifiedApprovalService.getPendingApprovalIds(),
            "count", unifiedApprovalService.getPendingCount(),
            "userId", userId,
            "timestamp", LocalDateTime.now()
        );
    }
    
    /**
     * 승인 통계 조회
     */
    @MessageMapping("/soar/stats")
    @SendToUser("/queue/approval-stats")
    public Map<String, Object> getApprovalStatistics(Principal principal) {
        log.debug("승인 통계 조회");
        
        Map<String, Object> stats = unifiedApprovalService.getStatistics();
        stats.put("type", "APPROVAL_STATISTICS");
        stats.put("timestamp", LocalDateTime.now());
        
        return stats;
    }
    
    /**
     * 승인 요청 전송 (서버 -> 클라이언트)
     * 
     * 새로운 승인 요청을 단일 토픽으로 브로드캐스트합니다.
     * 중복 방지를 위해 /topic/soar/approvals 토픽으로만 전송
     */
    public void sendApprovalRequest(ApprovalRequest request) {
        try {
            if (brokerTemplate == null) {
                log.error("SimpMessagingTemplate이 null입니다. WebSocket 설정을 확인하세요.");
                return;
            }
            
            // 메시지 생성 - 완전한 정보 포함
            Map<String, Object> message = new HashMap<>();
            message.put("type", "APPROVAL_REQUEST");
            message.put("approvalId", request.getRequestId());
            message.put("requestId", request.getRequestId()); // 호환성을 위해 중복
            message.put("toolName", request.getToolName());
            message.put("description", request.getActionDescription() != null ? 
                       request.getActionDescription() : request.getToolDescription());
            message.put("riskLevel", request.getRiskLevel().name());
            message.put("requestedBy", request.getRequestedBy());
            message.put("timestamp", LocalDateTime.now().toString());
            message.put("parameters", request.getParameters());
            message.put("sessionId", request.getSessionId());
            // 메시지 ID 추가 (중복 방지용)
            message.put("messageId", request.getRequestId() + "_" + System.currentTimeMillis());
            
            log.info("========================================");
            log.info("WebSocket 메시지 전송 시작");
            log.info("메시지 타입: APPROVAL_REQUEST");
            log.info("승인 ID: {}", request.getRequestId());
            log.info("도구명: {}", request.getToolName());
            log.info("위험도: {}", request.getRiskLevel());
            log.info("현재 활성 세션 수: {}", activeUserSessions.size());
            
            if (activeUserSessions.isEmpty()) {
                log.warn("경고: 활성 WebSocket 세션이 없습니다! 클라이언트가 연결되어 있는지 확인하세요.");
            }
            
            // 단일 토픽으로만 전송 (중복 방지)
            try {
                brokerTemplate.convertAndSend(TOPIC_APPROVALS, message);
                log.info("{} 토픽으로 메시지 전송 완료", TOPIC_APPROVALS);
                log.debug("전송된 메시지 ID: {}", message.get("messageId"));
            } catch (Exception ex) {
                log.error("{} 토픽 전송 실패: {}", TOPIC_APPROVALS, ex.getMessage(), ex);
            }
            
            log.info("WebSocket 승인 요청 브로드캐스트 완료: {}", request.getRequestId());
            log.info("========================================");
            
        } catch (Exception e) {
            log.error("WebSocket 승인 요청 전송 실패: {}", request.getRequestId(), e);
        }
    }
    
    /**
     * 타임아웃 알림 브로드캐스트
     * 
     * 승인 요청이 타임아웃되었음을 개별 결과 토픽으로만 알립니다.
     */
    public void broadcastTimeoutNotification(String approvalId, Map<String, Object> timeoutData) {
        try {
            // 메시지 ID 추가 (중복 방지용)
            Map<String, Object> message = new HashMap<>(timeoutData);
            message.put("messageId", approvalId + "_timeout_" + System.currentTimeMillis());
            
            // 특정 승인 ID 토픽으로만 전송 (중복 방지)
            brokerTemplate.convertAndSend(
                TOPIC_APPROVAL_RESULT + approvalId, 
                message
            );
            
            log.info("WebSocket 타임아웃 알림 전송: {} -> {}", approvalId, TOPIC_APPROVAL_RESULT + approvalId);
            
        } catch (Exception e) {
            log.error("타임아웃 알림 브로드캐스트 실패", e);
        }
    }
    
    /**
     * 승인 결과 브로드캐스트
     * 개별 결과 토픽으로만 전송 (중복 방지)
     */
    private void broadcastApprovalResult(String approvalId, Map<String, Object> result) {
        try {
            // 새로운 가변 Map 생성하여 메시지 ID 추가
            Map<String, Object> message = new HashMap<>(result);
            message.put("messageId", approvalId + "_result_" + System.currentTimeMillis());
            
            // 특정 승인 ID 토픽으로만 전송 (중복 방지)
            brokerTemplate.convertAndSend(
                TOPIC_APPROVAL_RESULT + approvalId, 
                message
            );
            
            log.debug("승인 결과 전송: {} -> {}", approvalId, TOPIC_APPROVAL_RESULT + approvalId);
            
        } catch (Exception e) {
            log.error("승인 결과 브로드캐스트 실패", e);
        }
    }
    
    /**
     * 타임아웃 알림 전송
     */
    public void sendTimeoutNotification(String approvalId, long timeoutSeconds) {
        Map<String, Object> message = Map.of(
            "type", "APPROVAL_TIMEOUT",
            "approvalId", approvalId,
            "timeoutSeconds", timeoutSeconds,
            "timestamp", LocalDateTime.now()
        );
        
        brokerTemplate.convertAndSend(
            TOPIC_APPROVAL_RESULT + approvalId, 
            message
        );
        
        log.warn("WebSocket 타임아웃 알림: {} ({}초)", approvalId, timeoutSeconds);
    }
    
    /**
     * 오류 알림 전송
     */
    public void sendErrorNotification(String approvalId, String error) {
        Map<String, Object> message = Map.of(
            "type", "APPROVAL_ERROR",
            "approvalId", approvalId,
            "error", error,
            "timestamp", LocalDateTime.now()
        );
        
        brokerTemplate.convertAndSend(
            TOPIC_APPROVAL_RESULT + approvalId, 
            message
        );
        
        log.error("WebSocket 오류 알림: {} - {}", approvalId, error);
    }
    
    /**
     * 범용 메시지 브로드캐스트 메소드
     * 
     * @param topic 전송할 토픽
     * @param data 전송할 데이터
     */
    public void broadcastMessage(String topic, Map<String, Object> data) {
        try {
            brokerTemplate.convertAndSend(topic, data);
            log.debug("WebSocket 메시지 브로드캐스트: {} -> {}", topic, data);
        } catch (Exception e) {
            log.error("WebSocket 메시지 브로드캐스트 실패: {}", topic, e);
        }
    }
    
    /**
     * WebSocket Heartbeat 전송
     * 
     * 모든 활성 WebSocket 연결에 대해 heartbeat를 전송합니다.
     * McpApprovalNotificationService에서 호출됩니다.
     */
    public void sendHeartbeat() {
        Map<String, Object> heartbeatMessage = Map.of(
            "type", "HEARTBEAT",
            "message", "WebSocket connection alive",
            "timestamp", LocalDateTime.now(),
            "activeSessions", activeUserSessions.size()
        );
        
        try {
            // 모든 구독자에게 heartbeat 브로드캐스트
            brokerTemplate.convertAndSend(TOPIC_APPROVALS, heartbeatMessage);
            log.trace("💓 WebSocket Heartbeat 전송 완료: {} 활성 세션", activeUserSessions.size());
            
        } catch (Exception e) {
            log.error("WebSocket Heartbeat 전송 실패", e);
        }
    }
    
    /**
     * 사용자 세션 등록
     * 
     * WebSocket 연결 시 세션을 등록합니다.
     */
    public void registerUserSession(String sessionId, String userId) {
        activeUserSessions.put(sessionId, userId);
        log.debug("WebSocket 세션 등록: {} -> {}", sessionId, userId);
    }
    
    /**
     * 사용자 세션 제거
     * 
     * WebSocket 연결 종료 시 세션을 제거합니다.
     */
    public void removeUserSession(String sessionId) {
        String userId = activeUserSessions.remove(sessionId);
        if (userId != null) {
            log.debug("WebSocket 세션 제거: {} (사용자: {})", sessionId, userId);
        }
    }
    
    /**
     * 활성 세션 수 조회
     */
    public int getActiveSessionCount() {
        return activeUserSessions.size();
    }
    
    /**
     * 테스트용 브로드캐스트 메시지 전송
     * WebSocket 브로드캐스트가 정상 작동하는지 테스트
     */
    public void sendTestBroadcast(String message) {
        if (brokerTemplate == null) {
            log.error("TEST: SimpMessagingTemplate이 null입니다!");
            return;
        }
        
        Map<String, Object> testMessage = new HashMap<>();
        testMessage.put("type", "TEST_BROADCAST");
        testMessage.put("message", message);
        testMessage.put("timestamp", LocalDateTime.now().toString());
        testMessage.put("activeSessions", activeUserSessions.size());
        
        log.info("🧪 TEST: 브로드캐스트 시작");
        
        // /topic/test로 전송
        try {
            brokerTemplate.convertAndSend("/topic/test", testMessage);
            log.info("TEST: /topic/test로 전송 완료");
        } catch (Exception e) {
            log.error("TEST: /topic/test 전송 실패", e);
        }
        
        // /topic/soar/approvals로도 전송
        try {
            brokerTemplate.convertAndSend("/topic/soar/approvals", testMessage);
            log.info("TEST: /topic/soar/approvals로 전송 완료");
        } catch (Exception e) {
            log.error("TEST: /topic/soar/approvals 전송 실패", e);
        }
    }
}