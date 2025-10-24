package io.contexa.contexacore.std.components.event;

import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.context.DomainContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * IAM 감사 로거
 * 
 * 완전한 감사 추적 시스템
 * - 모든 IAM 작업 로깅
 * - 성능 메트릭 수집
 * - 보안 이벤트 추적
 * - 규정 준수 지원
 */
@Component
public class AuditLogger {
    
    private static final Logger log = LoggerFactory.getLogger(AuditLogger.class);
    private static final Logger auditLog = LoggerFactory.getLogger("IAM_AUDIT");
    
    private final ConcurrentMap<String, AuditEntry> activeAudits = new ConcurrentHashMap<>();
    
    /**
     * 감사 시작
     */
    public <T extends DomainContext> String startAudit(AIRequest<T> request) {
        String auditId = generateAuditId();
        
        AuditEntry entry = new AuditEntry(
            auditId,
            request.getClass().getSimpleName(),
            request.getContext().getClass().getSimpleName(),
            LocalDateTime.now(),
            getCurrentUser(),
            getClientInfo()
        );
        
        activeAudits.put(auditId, entry);
        
        auditLog.info("AUDIT_START: {} - Operation: {} - Context: {} - User: {} - Client: {}", 
                     auditId, entry.operationType, entry.contextType, entry.userId, entry.clientInfo);
        
        return auditId;
    }
    
    /**
     * 감사 완료
     */
    public <T extends DomainContext, R extends AIResponse> void completeAudit(
            String auditId, AIRequest<T> request, R response) {
        
        AuditEntry entry = activeAudits.remove(auditId);
        if (entry == null) {
            log.warn("Audit entry not found for ID: {}", auditId);
            return;
        }
        
        entry.endTime = LocalDateTime.now();
        entry.duration = java.time.Duration.between(entry.startTime, entry.endTime).toMillis();
        entry.status = "SUCCESS";
        entry.responseType = response.getClass().getSimpleName();
        
        auditLog.info("AUDIT_SUCCESS: {} - Duration: {}ms - Response: {} - Status: {}", 
                     auditId, entry.duration, entry.responseType, response.getStatus());
        
        // 메트릭 수집
        collectMetrics(entry, request, response);
    }
    
    /**
     * 감사 실패
     */
    public <T extends DomainContext> void failAudit(String auditId, AIRequest<T> request, Exception error) {
        AuditEntry entry = activeAudits.remove(auditId);
        if (entry == null) {
            log.warn("Audit entry not found for ID: {}", auditId);
            return;
        }
        
        entry.endTime = LocalDateTime.now();
        entry.duration = java.time.Duration.between(entry.startTime, entry.endTime).toMillis();
        entry.status = "FAILED";
        entry.errorMessage = error.getMessage();
        entry.errorType = error.getClass().getSimpleName();
        
        auditLog.error("AUDIT_FAILED: {} - Duration: {}ms - Error: {} - Message: {}", 
                      auditId, entry.duration, entry.errorType, entry.errorMessage);
        
        // 보안 이벤트 체크
        checkSecurityEvent(entry, request, error);
    }
    
    // ==================== Private Methods ====================
    
    private String generateAuditId() {
        return "AUDIT-" + UUID.randomUUID().toString().substring(0, 8);
    }
    
    private String getCurrentUser() {
        try {
            return org.springframework.security.core.context.SecurityContextHolder
                    .getContext().getAuthentication().getName();
        } catch (Exception e) {
            return "SYSTEM";
        }
    }
    
    private String getClientInfo() {
        // HTTP 요청에서 클라이언트 정보 추출
        try {
            RequestAttributes attrs =
                RequestContextHolder.getRequestAttributes();
            if (attrs instanceof ServletRequestAttributes servletAttrs) {
                String remoteAddr = servletAttrs.getRequest().getRemoteAddr();
                int remotePort = servletAttrs.getRequest().getRemotePort();
                return remoteAddr + ":" + remotePort;
            }
        } catch (Exception e) {
            // TODO  웹 컨텍스트가 없는 경우 (배치 작업 등)
        }
        return "INTERNAL";
    }
    
    private <T extends DomainContext, R extends AIResponse> void collectMetrics(
            AuditEntry entry, AIRequest<T> request, R response) {
        // 성능 메트릭 수집
        log.debug("Metrics - Operation: {} - Duration: {}ms - Success: true", 
                 entry.operationType, entry.duration);
        
        // TODO 추가 메트릭 수집 로직...
    }
    
    private <T extends DomainContext> void checkSecurityEvent(
            AuditEntry entry, AIRequest<T> request, Exception error) {
        // 보안 이벤트 감지
        if (error instanceof SecurityException || error.getMessage().contains("access denied")) {
            auditLog.warn("SECURITY_EVENT: {} - Potential security violation detected - User: {} - Operation: {}", 
                         entry.auditId, entry.userId, entry.operationType);
        }
    }
    
    // ==================== Inner Classes ====================
    
    private static class AuditEntry {
        final String auditId;
        final String operationType;
        final String contextType;
        final LocalDateTime startTime;
        final String userId;
        final String clientInfo;
        
        LocalDateTime endTime;
        long duration;
        String status;
        String responseType;
        String errorMessage;
        String errorType;
        
        AuditEntry(String auditId, String operationType, String contextType, 
                  LocalDateTime startTime, String userId, String clientInfo) {
            this.auditId = auditId;
            this.operationType = operationType;
            this.contextType = contextType;
            this.startTime = startTime;
            this.userId = userId;
            this.clientInfo = clientInfo;
        }
    }
} 