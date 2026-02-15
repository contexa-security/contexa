package io.contexa.contexacoreenterprise.soar.manager;

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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.io.Serializable;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
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

    private final Map<String, InteractionSession> sessionCache = new ConcurrentHashMap<>();
    
    private static final String SESSION_KEY_PREFIX = "soar:session:";
    private static final String APPROVAL_KEY_PREFIX = "soar:approval:";
    private static final Duration SESSION_TTL = Duration.ofHours(2);
    private static final Duration APPROVAL_TTL = Duration.ofMinutes(30);

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

        saveSession(session);

        notifySessionCreated(session);

        return sessionId;
    }

    public Optional<InteractionSession> getSession(String sessionId) {
        
        String key = SESSION_KEY_PREFIX + sessionId;
        InteractionSession session = (InteractionSession) redisTemplate.opsForValue().get(key);
        
        if (session == null) {
            
            session = sessionCache.get(sessionId);
        }
        
        return Optional.ofNullable(session);
    }

    public SessionStatus getSessionStatus(String sessionId) {
        return getSession(sessionId)
            .map(InteractionSession::getStatus)
            .orElse(SessionStatus.NOT_FOUND);
    }

    public void updateSession(InteractionSession session) {
        session.setLastActivityAt(LocalDateTime.now());
        saveSession(session);

        notifySessionUpdated(session);
    }

    public Mono<Boolean> waitForApproval(String toolName, String sessionId) {
        return createApprovalRequest(toolName, sessionId)
            .flatMap(this::pollApprovalStatus);
    }

    private Mono<String> createApprovalRequest(String toolName, String sessionId) {
        return Mono.fromCallable(() -> {
            Optional<InteractionSession> sessionOpt = getSession(sessionId);
            if (sessionOpt.isEmpty()) {
                throw new IllegalArgumentException("Session not found: " + sessionId);
            }
            
            InteractionSession session = sessionOpt.get();

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

            SoarContext context = new SoarContext();
            context.setSessionId(sessionId);
            context.setIncidentId(session.getIncidentId());
            context.setOrganizationId(session.getOrganizationId());
            
            String requestId = approvalService.requestApproval(context, details);

            ApprovalRequestInfo requestInfo = ApprovalRequestInfo.builder()
                .requestId(requestId)
                .toolName(toolName)
                .requestedAt(LocalDateTime.now())
                .status(io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus.PENDING)
                .build();
            
            session.getApprovalRequests().add(requestInfo);
            session.setInteractionCount(session.getInteractionCount() + 1);
            updateSession(session);

            sendApprovalRequest(requestId, toolName, sessionId);

            return requestId;
        });
    }

    private Mono<Boolean> pollApprovalStatus(String requestId) {
        // Use interval-based polling instead of recursive calls to prevent stack overflow
        return Flux.interval(Duration.ofSeconds(1))
            .flatMap(tick -> Mono.fromCallable(() -> approvalService.getApprovalStatus(requestId)))
            .filter(status -> status == io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus.APPROVED
                    || status == io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus.REJECTED)
            .next()
            .map(status -> status == io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus.APPROVED)
            .timeout(Duration.ofMinutes(5))
            .onErrorReturn(false);
    }

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

            notifyToolExecuted(sessionId, toolName, success);
            
                    });
    }

    public void addConversationEntry(String sessionId, String role, String message) {
        getSession(sessionId).ifPresent(session -> {
            ConversationEntry entry = ConversationEntry.builder()
                .role(role)
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();
            
            session.getConversationHistory().add(entry);

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

    public void closeSession(String sessionId, String reason) {
        getSession(sessionId).ifPresent(session -> {
            session.setStatus(SessionStatus.CLOSED);
            session.setClosedAt(LocalDateTime.now());
            session.getMetadata().put("closeReason", reason);
            
            updateSession(session);

            notifySessionClosed(sessionId, reason);
            
                    });
    }

    public List<InteractionSession> getActiveSessions() {
        // Use SCAN instead of keys() to avoid blocking Redis
        List<InteractionSession> sessions = new ArrayList<>();
        try (var cursor = redisTemplate.scan(
                org.springframework.data.redis.core.ScanOptions.scanOptions()
                    .match(SESSION_KEY_PREFIX + "*")
                    .count(100)
                    .build())) {
            while (cursor.hasNext()) {
                String key = (String) cursor.next();
                InteractionSession session = (InteractionSession) redisTemplate.opsForValue().get(key);
                if (session != null && session.getStatus() == SessionStatus.ACTIVE) {
                    sessions.add(session);
                }
            }
        }
        return sessions;
    }

    private void saveSession(InteractionSession session) {
        String key = SESSION_KEY_PREFIX + session.getSessionId();
        redisTemplate.opsForValue().set(key, session, SESSION_TTL);
        sessionCache.put(session.getSessionId(), session); 
    }

    private void sendApprovalRequest(String requestId, String toolName, String sessionId) {
        Map<String, Object> request = Map.of(
            "type", "APPROVAL_REQUEST",
            "requestId", requestId,
            "toolName", toolName,
            "sessionId", sessionId,
            "timestamp", LocalDateTime.now()
        );
        brokerTemplate.convertAndSend("/topic/soar/approvals", (Object) request);
    }
    
    private void notifySessionCreated(InteractionSession session) {
        Map<String, Object> notification = Map.of(
            "type", "SESSION_CREATED",
            "sessionId", session.getSessionId(),
            "incidentId", session.getIncidentId(),
            "timestamp", LocalDateTime.now()
        );
        brokerTemplate.convertAndSend("/topic/soar/sessions", (Object) notification);
    }
    
    private void notifySessionUpdated(InteractionSession session) {
        Map<String, Object> notification = Map.of(
            "type", "SESSION_UPDATED",
            "sessionId", session.getSessionId(),
            "status", session.getStatus(),
            "timestamp", LocalDateTime.now()
        );
        brokerTemplate.convertAndSend("/topic/soar/sessions", (Object) notification);
    }
    
    private void notifySessionClosed(String sessionId, String reason) {
        Map<String, Object> notification = Map.of(
            "type", "SESSION_CLOSED",
            "sessionId", sessionId,
            "reason", reason,
            "timestamp", LocalDateTime.now()
        );
        brokerTemplate.convertAndSend("/topic/soar/sessions",(Object)  notification);
    }
    
    private void notifyToolExecuted(String sessionId, String toolName, boolean success) {
        Map<String, Object> notification = Map.of(
            "type", "TOOL_EXECUTED",
            "sessionId", sessionId,
            "toolName", toolName,
            "success", success,
            "timestamp", LocalDateTime.now()
        );
        brokerTemplate.convertAndSend("/topic/soar/tools",(Object)  notification);
    }

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