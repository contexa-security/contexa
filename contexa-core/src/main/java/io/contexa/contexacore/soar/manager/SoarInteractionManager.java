package io.contexa.contexacore.soar.manager;

import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.soar.approval.ApprovalRequestDetails;
import io.contexa.contexacore.soar.approval.ApprovalService;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.io.Serializable;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SOAR 상호작용 관리자
 * 
 * AI 진단 프로세스와 Human-in-the-Loop를 연결하여
 * 지속적인 상호작용 진단을 가능하게 합니다.
 */
@Slf4j
@Component
public class SoarInteractionManager {
    
    private final RedisTemplate<String, Object> redisTemplate;
    private final SimpMessagingTemplate brokerTemplate;
    private final ApprovalService approvalService;
    
    public SoarInteractionManager(
            RedisTemplate<String, Object> redisTemplate,
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate,
            ApprovalService approvalService) {
        this.redisTemplate = redisTemplate;
        this.brokerTemplate = brokerTemplate;
        this.approvalService = approvalService;
    }
    
    // 메모리 캐시 (Redis 장애 시 fallback)
    private final Map<String, InteractionSession> sessionCache = new ConcurrentHashMap<>();
    
    private static final String SESSION_KEY_PREFIX = "soar:session:";
    private static final String APPROVAL_KEY_PREFIX = "soar:approval:";
    private static final Duration SESSION_TTL = Duration.ofHours(2);
    private static final Duration APPROVAL_TTL = Duration.ofMinutes(30);
    
    /**
     * 새로운 SOAR 상호작용 세션 생성
     */
    public String createSession(SoarContext context) {
        String sessionId = UUID.randomUUID().toString();
        
        InteractionSession session = InteractionSession.builder()
            .sessionId(sessionId)
            .incidentId(context.getIncidentId())
            .userId(context.getUserId())
            .organizationId(context.getOrganizationId())
            .threatLevel(context.getThreatLevel())
            .status(SessionStatus.ACTIVE)
            .createdAt(LocalDateTime.now())
            .lastActivityAt(LocalDateTime.now())
            .interactionCount(0)
            .approvalRequests(new ArrayList<>())
            .executedTools(new ArrayList<>())
            .conversationHistory(new ArrayList<>())
            .metadata(new HashMap<>())
            .build();
        
        // Redis 저장
        saveSession(session);
        
        // WebSocket 으로 세션 생성 알림
        notifySessionCreated(session);
        
        log.info("SOAR 상호작용 세션 생성: sessionId={}, incidentId={}", 
            sessionId, context.getIncidentId());
        
        return sessionId;
    }
    
    /**
     * 기존 세션 조회
     */
    public Optional<InteractionSession> getSession(String sessionId) {
        // Redis에서 먼저 조회
        String key = SESSION_KEY_PREFIX + sessionId;
        InteractionSession session = (InteractionSession) redisTemplate.opsForValue().get(key);
        
        if (session == null) {
            // 메모리 캐시 fallback
            session = sessionCache.get(sessionId);
        }
        
        return Optional.ofNullable(session);
    }
    
    /**
     * 세션 상태 조회
     */
    public SessionStatus getSessionStatus(String sessionId) {
        return getSession(sessionId)
            .map(InteractionSession::getStatus)
            .orElse(SessionStatus.NOT_FOUND);
    }
    
    /**
     * 세션 업데이트
     */
    public void updateSession(InteractionSession session) {
        session.setLastActivityAt(LocalDateTime.now());
        saveSession(session);
        
        // WebSocket으로 세션 업데이트 알림
        notifySessionUpdated(session);
    }
    
    /**
     * 도구 실행 승인 대기
     */
    public Mono<Boolean> waitForApproval(String toolName, String sessionId) {
        return createApprovalRequest(toolName, sessionId)
            .flatMap(this::pollApprovalStatus);
    }
    
    /**
     * 승인 요청 생성
     */
    private Mono<String> createApprovalRequest(String toolName, String sessionId) {
        return Mono.fromCallable(() -> {
            Optional<InteractionSession> sessionOpt = getSession(sessionId);
            if (sessionOpt.isEmpty()) {
                throw new IllegalArgumentException("Session not found: " + sessionId);
            }
            
            InteractionSession session = sessionOpt.get();
            
            // ApprovalService를 통해 승인 요청 생성
            ApprovalRequestDetails details = new ApprovalRequestDetails(
                toolName,
                String.format("Tool execution approval required: %s", toolName),null,null,null,
                Map.of(
                    "sessionId", sessionId,
                    "toolName", toolName,
                    "incidentId", session.getIncidentId(),
                    "timestamp", LocalDateTime.now().toString()
                )
            );
            
            // SoarContext 생성 (ApprovalService에 필요)
            SoarContext context = new SoarContext();
            context.setSessionId(sessionId);
            context.setIncidentId(session.getIncidentId());
            context.setOrganizationId(session.getOrganizationId());
            
            String requestId = approvalService.requestApproval(context, details);
            
            // 세션에 승인 요청 추가
            ApprovalRequestInfo requestInfo = ApprovalRequestInfo.builder()
                .requestId(requestId)
                .toolName(toolName)
                .requestedAt(LocalDateTime.now())
                .status(io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus.PENDING)
                .build();
            
            session.getApprovalRequests().add(requestInfo);
            session.setInteractionCount(session.getInteractionCount() + 1);
            updateSession(session);
            
            // WebSocket으로 승인 요청 전송
            sendApprovalRequest(requestId, toolName, sessionId);
            
            log.info("승인 요청 생성: requestId={}, tool={}, session={}", 
                requestId, toolName, sessionId);
            
            return requestId;
        });
    }
    
    /**
     * 승인 상태 폴링
     */
    private Mono<Boolean> pollApprovalStatus(String requestId) {
        return Mono.defer(() -> {
            io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus status = approvalService.getApprovalStatus(requestId);
            
            if (status == io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus.APPROVED) {
                log.info("도구 실행 승인됨: requestId={}", requestId);
                return Mono.just(true);
            } else if (status == io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus.REJECTED) {
                log.info("도구 실행 거부됨: requestId={}", requestId);
                return Mono.just(false);
            } else {
                // PENDING 상태면 재시도
                return Mono.delay(Duration.ofSeconds(1))
                    .flatMap(tick -> pollApprovalStatus(requestId));
            }
        })
        .timeout(Duration.ofMinutes(5)) // 5분 타임아웃
        .onErrorReturn(false); // 타임아웃 시 false 반환
    }
    
    /**
     * 도구 실행 기록
     */
    public void recordToolExecution(String sessionId, String toolName, boolean success, String result) {
        getSession(sessionId).ifPresent(session -> {
            ExecutedToolInfo toolInfo = ExecutedToolInfo.builder()
                .toolName(toolName)
                .executedAt(LocalDateTime.now())
                .success(success)
                .result(result)
                .build();
            
            session.getExecutedTools().add(toolInfo);
            updateSession(session);
            
            // WebSocket으로 실행 결과 알림
            notifyToolExecuted(sessionId, toolName, success);
            
            log.info("🔨 도구 실행 기록: tool={}, success={}, sessionId={}", 
                toolName, success, sessionId);
        });
    }
    
    /**
     * 대화 히스토리 추가
     */
    public void addConversationEntry(String sessionId, String role, String message) {
        getSession(sessionId).ifPresent(session -> {
            ConversationEntry entry = ConversationEntry.builder()
                .role(role)
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();
            
            session.getConversationHistory().add(entry);
            
            // 최대 100개까지만 유지
            if (session.getConversationHistory().size() > 100) {
                session.setConversationHistory(
                    new ArrayList<>(session.getConversationHistory().subList(
                        session.getConversationHistory().size() - 100,
                        session.getConversationHistory().size()
                    ))
                );
            }
            
            updateSession(session);
        });
    }
    
    /**
     * 세션 종료
     */
    public void closeSession(String sessionId, String reason) {
        getSession(sessionId).ifPresent(session -> {
            session.setStatus(SessionStatus.CLOSED);
            session.setClosedAt(LocalDateTime.now());
            session.getMetadata().put("closeReason", reason);
            
            updateSession(session);
            
            // WebSocket으로 세션 종료 알림
            notifySessionClosed(sessionId, reason);
            
            log.info("SOAR 세션 종료: sessionId={}, reason={}", sessionId, reason);
        });
    }
    
    /**
     * 활성 세션 목록 조회
     */
    public List<InteractionSession> getActiveSessions() {
        Set<String> sessionKeys = redisTemplate.keys(SESSION_KEY_PREFIX + "*");
        if (sessionKeys == null) return new ArrayList<>();
        
        List<InteractionSession> sessions = new ArrayList<>();
        
        for (String key : sessionKeys) {
            InteractionSession session = (InteractionSession) redisTemplate.opsForValue().get(key);
            if (session != null && session.getStatus() == SessionStatus.ACTIVE) {
                sessions.add(session);
            }
        }
        
        return sessions;
    }
    
    // === Private Helper Methods ===
    
    private void saveSession(InteractionSession session) {
        String key = SESSION_KEY_PREFIX + session.getSessionId();
        redisTemplate.opsForValue().set(key, session, SESSION_TTL);
        sessionCache.put(session.getSessionId(), session); // 메모리 캐시 업데이트
    }
    
    // === WebSocket Notification Methods ===
    
    private void sendApprovalRequest(String requestId, String toolName, String sessionId) {
        Map<String, Object> request = Map.of(
            "type", "APPROVAL_REQUEST",
            "requestId", requestId,
            "toolName", toolName,
            "sessionId", sessionId,
            "timestamp", LocalDateTime.now()
        );
        brokerTemplate.convertAndSend("/topic/soar/approvals", request);
    }
    
    private void notifySessionCreated(InteractionSession session) {
        Map<String, Object> notification = Map.of(
            "type", "SESSION_CREATED",
            "sessionId", session.getSessionId(),
            "incidentId", session.getIncidentId(),
            "timestamp", LocalDateTime.now()
        );
        brokerTemplate.convertAndSend("/topic/soar/sessions", notification);
    }
    
    private void notifySessionUpdated(InteractionSession session) {
        Map<String, Object> notification = Map.of(
            "type", "SESSION_UPDATED",
            "sessionId", session.getSessionId(),
            "status", session.getStatus(),
            "timestamp", LocalDateTime.now()
        );
        brokerTemplate.convertAndSend("/topic/soar/sessions", notification);
    }
    
    private void notifySessionClosed(String sessionId, String reason) {
        Map<String, Object> notification = Map.of(
            "type", "SESSION_CLOSED",
            "sessionId", sessionId,
            "reason", reason,
            "timestamp", LocalDateTime.now()
        );
        brokerTemplate.convertAndSend("/topic/soar/sessions", notification);
    }
    
    private void notifyToolExecuted(String sessionId, String toolName, boolean success) {
        Map<String, Object> notification = Map.of(
            "type", "TOOL_EXECUTED",
            "sessionId", sessionId,
            "toolName", toolName,
            "success", success,
            "timestamp", LocalDateTime.now()
        );
        brokerTemplate.convertAndSend("/topic/soar/tools", notification);
    }
    
    // === Inner Classes ===
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class InteractionSession implements Serializable {
        private String sessionId;
        private String incidentId;
        private String userId;
        private String organizationId;
        private SoarContext.ThreatLevel threatLevel;
        private SessionStatus status;
        private LocalDateTime createdAt;
        private LocalDateTime lastActivityAt;
        private LocalDateTime closedAt;
        private int interactionCount;
        private List<ApprovalRequestInfo> approvalRequests;
        private List<ExecutedToolInfo> executedTools;
        private List<ConversationEntry> conversationHistory;
        private Map<String, Object> metadata;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ApprovalRequestInfo {
        private String requestId;
        private String toolName;
        private LocalDateTime requestedAt;
        private LocalDateTime respondedAt;
        private io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus status;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ExecutedToolInfo {
        private String toolName;
        private LocalDateTime executedAt;
        private boolean success;
        private String result;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ConversationEntry {
        private String role;
        private String message;
        private LocalDateTime timestamp;
    }
    
    public enum SessionStatus {
        ACTIVE,
        PAUSED,
        WAITING,
        CLOSED,
        EXPIRED,
        NOT_FOUND
    }
}