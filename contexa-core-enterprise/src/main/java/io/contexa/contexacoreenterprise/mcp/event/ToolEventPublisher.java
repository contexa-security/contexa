package io.contexa.contexacoreenterprise.mcp.event;
import io.contexa.contexacommon.enums.RiskLevel;

import io.contexa.contexacoreenterprise.autonomous.workflow.ApprovalWorkflow;
import io.contexa.contexacoreenterprise.mcp.tool.execution.ToolExecutor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;

import java.time.Instant;
import java.util.UUID;

/**
 * ToolEventPublisher
 * 
 * 도구 실행 관련 이벤트를 발행합니다.
 * Spring의 ApplicationEvent 시스템을 사용합니다.
 */
@Slf4j
@RequiredArgsConstructor
public class ToolEventPublisher {
    
    private final ApplicationEventPublisher eventPublisher;
    
    /**
     * 도구 실행 시작 이벤트 발행
     */
    @Async
    public void publishToolExecutionStarted(
            String toolName,
            ToolExecutor.ToolRequest request,
            ToolExecutor.ExecutionContext context) {
        
        ToolExecutionEvent event = ToolExecutionEvent.builder()
            .eventId(generateEventId())
            .eventType(EventType.EXECUTION_STARTED)
            .toolName(toolName)
            .request(request)
            .context(context)
            .timestamp(Instant.now())
            .build();
        
        log.debug("도구 실행 시작 이벤트 발행: {}", toolName);
        eventPublisher.publishEvent(event);
    }
    
    /**
     * 도구 실행 완료 이벤트 발행
     */
    @Async
    public void publishToolExecutionCompleted(
            String toolName,
            ToolExecutor.ToolRequest request,
            ToolExecutor.ExecutionContext context,
            ToolExecutor.ToolResult result,
            long durationMs) {
        
        ToolExecutionEvent event = ToolExecutionEvent.builder()
            .eventId(generateEventId())
            .eventType(EventType.EXECUTION_COMPLETED)
            .toolName(toolName)
            .request(request)
            .context(context)
            .result(result)
            .durationMs(durationMs)
            .timestamp(Instant.now())
            .build();
        
        log.debug("도구 실행 완료 이벤트 발행: {} ({}ms)", toolName, durationMs);
        eventPublisher.publishEvent(event);
    }
    
    /**
     * 도구 실행 실패 이벤트 발행
     */
    @Async
    public void publishToolExecutionFailed(
            String toolName,
            ToolExecutor.ToolRequest request,
            ToolExecutor.ExecutionContext context,
            Exception error,
            long durationMs) {
        
        ToolExecutionEvent event = ToolExecutionEvent.builder()
            .eventId(generateEventId())
            .eventType(EventType.EXECUTION_FAILED)
            .toolName(toolName)
            .request(request)
            .context(context)
            .error(error)
            .errorMessage(error.getMessage())
            .durationMs(durationMs)
            .timestamp(Instant.now())
            .build();
        
        log.warn("도구 실행 실패 이벤트 발행: {} - {}", toolName, error.getMessage());
        eventPublisher.publishEvent(event);
    }
    
    /**
     * 승인 요청 이벤트 발행
     */
    @Async
    public void publishApprovalRequested(
            String toolName,
            ToolExecutor.ToolRequest request,
            ToolExecutor.ExecutionContext context,
            io.contexa.contexacommon.enums.RiskLevel riskLevel) {
        
        ApprovalEvent event = ApprovalEvent.builder()
            .eventId(generateEventId())
            .eventType(ApprovalEventType.APPROVAL_REQUESTED)
            .toolName(toolName)
            .request(request)
            .context(context)
            .riskLevel(riskLevel)
            .timestamp(Instant.now())
            .build();
        
        log.info("승인 요청 이벤트 발행: {} (위험도: {})", toolName, riskLevel);
        eventPublisher.publishEvent(event);
    }
    
    /**
     * 승인 완료 이벤트 발행
     */
    @Async
    public void publishApprovalGranted(
            String toolName,
            String approver,
            String reason) {
        
        ApprovalEvent event = ApprovalEvent.builder()
            .eventId(generateEventId())
            .eventType(ApprovalEventType.APPROVAL_GRANTED)
            .toolName(toolName)
            .approver(approver)
            .reason(reason)
            .timestamp(Instant.now())
            .build();
        
        log.info("승인 완료 이벤트 발행: {} by {}", toolName, approver);
        eventPublisher.publishEvent(event);
    }
    
    /**
     * 승인 거부 이벤트 발행
     */
    @Async
    public void publishApprovalDenied(
            String toolName,
            String denier,
            String reason) {
        
        ApprovalEvent event = ApprovalEvent.builder()
            .eventId(generateEventId())
            .eventType(ApprovalEventType.APPROVAL_DENIED)
            .toolName(toolName)
            .approver(denier)
            .reason(reason)
            .timestamp(Instant.now())
            .build();
        
        log.info("승인 거부 이벤트 발행: {} by {}", toolName, denier);
        eventPublisher.publishEvent(event);
    }
    
    /**
     * 캐시 히트 이벤트 발행
     */
    @Async
    public void publishCacheHit(String toolName, String cacheKey) {
        CacheEvent event = CacheEvent.builder()
            .eventId(generateEventId())
            .eventType(CacheEventType.CACHE_HIT)
            .toolName(toolName)
            .cacheKey(cacheKey)
            .timestamp(Instant.now())
            .build();
        
        log.trace("캐시 히트 이벤트 발행: {}", cacheKey);
        eventPublisher.publishEvent(event);
    }
    
    /**
     * 캐시 미스 이벤트 발행
     */
    @Async
    public void publishCacheMiss(String toolName, String cacheKey) {
        CacheEvent event = CacheEvent.builder()
            .eventId(generateEventId())
            .eventType(CacheEventType.CACHE_MISS)
            .toolName(toolName)
            .cacheKey(cacheKey)
            .timestamp(Instant.now())
            .build();
        
        log.trace("캐시 미스 이벤트 발행: {}", cacheKey);
        eventPublisher.publishEvent(event);
    }
    
    /**
     * 보안 위반 이벤트 발행
     */
    public void publishSecurityViolation(
            String toolName,
            String violationType,
            String details,
            ToolExecutor.ExecutionContext context) {
        
        SecurityEvent event = SecurityEvent.builder()
            .eventId(generateEventId())
            .eventType(SecurityEventType.SECURITY_VIOLATION)
            .toolName(toolName)
            .violationType(violationType)
            .details(details)
            .context(context)
            .timestamp(Instant.now())
            .build();
        
        log.error("보안 위반 이벤트 발행: {} - {}", violationType, details);
        eventPublisher.publishEvent(event);
    }
    
    /**
     * 권한 거부 이벤트 발행
     */
    public void publishAuthorizationDenied(
            String toolName,
            String userId,
            String requiredPermission,
            ToolExecutor.ExecutionContext context) {
        
        SecurityEvent event = SecurityEvent.builder()
            .eventId(generateEventId())
            .eventType(SecurityEventType.AUTHORIZATION_DENIED)
            .toolName(toolName)
            .userId(userId)
            .requiredPermission(requiredPermission)
            .context(context)
            .timestamp(Instant.now())
            .build();
        
        log.warn("권한 거부 이벤트 발행: user={}, permission={}", userId, requiredPermission);
        eventPublisher.publishEvent(event);
    }
    
    /**
     * 이벤트 ID 생성
     */
    private String generateEventId() {
        return UUID.randomUUID().toString();
    }
    
    // 이벤트 클래스들
    
    /**
     * 도구 실행 이벤트
     */
    @Data
    @Builder
    public static class ToolExecutionEvent {
        private String eventId;
        private EventType eventType;
        private String toolName;
        private ToolExecutor.ToolRequest request;
        private ToolExecutor.ExecutionContext context;
        private ToolExecutor.ToolResult result;
        private Exception error;
        private String errorMessage;
        private long durationMs;
        private Instant timestamp;
    }
    
    /**
     * 승인 이벤트
     */
    @Data
    @Builder
    public static class ApprovalEvent {
        private String eventId;
        private ApprovalEventType eventType;
        private String toolName;
        private ToolExecutor.ToolRequest request;
        private ToolExecutor.ExecutionContext context;
        private io.contexa.contexacommon.enums.RiskLevel riskLevel;
        private String approver;
        private String reason;
        private Instant timestamp;
    }
    
    /**
     * 캐시 이벤트
     */
    @Data
    @Builder
    public static class CacheEvent {
        private String eventId;
        private CacheEventType eventType;
        private String toolName;
        private String cacheKey;
        private Instant timestamp;
    }
    
    /**
     * 보안 이벤트
     */
    @Data
    @Builder
    public static class SecurityEvent {
        private String eventId;
        private SecurityEventType eventType;
        private String toolName;
        private String violationType;
        private String details;
        private String userId;
        private String requiredPermission;
        private ToolExecutor.ExecutionContext context;
        private Instant timestamp;
    }
    
    /**
     * 이벤트 타입들
     */
    public enum EventType {
        EXECUTION_STARTED,
        EXECUTION_COMPLETED,
        EXECUTION_FAILED,
        EXECUTION_TIMEOUT,
        EXECUTION_CANCELLED
    }
    
    public enum ApprovalEventType {
        APPROVAL_REQUESTED,
        APPROVAL_GRANTED,
        APPROVAL_DENIED,
        APPROVAL_TIMEOUT,
        APPROVAL_AUTO_GRANTED
    }
    
    public enum CacheEventType {
        CACHE_HIT,
        CACHE_MISS,
        CACHE_PUT,
        CACHE_EVICT,
        CACHE_CLEAR
    }
    
    public enum SecurityEventType {
        SECURITY_VIOLATION,
        AUTHORIZATION_DENIED,
        AUTHENTICATION_FAILED,
        SUSPICIOUS_ACTIVITY,
        RATE_LIMIT_EXCEEDED
    }
}