package io.contexa.contexamcp.tools;

import io.contexa.contexacommon.annotation.SoarTool;
import io.contexa.contexamcp.service.AuditLogService;
import io.contexa.contexamcp.utils.SecurityToolUtils;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.List;

/**
 * Audit Log Query Tool
 *
 * 감사 로그를 조회하여 보안 위협을 분석합니다.
 * 사용자 ID 또는 IP 주소로 로그를 검색할 수 있습니다.
 *
 * Spring AI @Tool 어노테이션 기반 구현
 */
@Slf4j
@RequiredArgsConstructor
@SoarTool(
    name = "audit_log_query",
    description = "Query and analyze audit logs for security threats",
    riskLevel = SoarTool.RiskLevel.LOW,
    approval = SoarTool.ApprovalRequirement.AUTO,
    auditRequired = true,
    retryable = true,
    maxRetries = 3,
    timeoutMs = 30000,
    requiredPermissions = {"audit.read", "log.analyze"},
    allowedEnvironments = {"development", "staging", "production"}
)
public class AuditLogQueryTool {

    private final AuditLogService auditLogService;

    /**
     * 감사 로그 조회 및 분석
     * 
     * @param userId 조회할 사용자 ID
     * @param ipAddress 조회할 IP 주소
     * @param dateFrom 조회 시작 날짜 (ISO-8601 형식)
     * @param dateTo 조회 종료 날짜 (ISO-8601 형식)
     * @param limit 최대 결과 개수
     * @return 조회된 로그와 위협 분석 결과
     */
    @Tool(
        name = "queryAuditLogs", 
        description = """
            감사 로그를 조회하여 보안 위협을 분석합니다.
            사용자 ID, IP 주소, 날짜 범위로 로그를 검색할 수 있습니다.
            자동으로 위협 레벨을 분석하여 제공합니다.
            """
    )
    @Cacheable("soar-audit-logs")
    public Response queryAuditLogs(
        @ToolParam(description = "조회할 사용자 ID", required = false) 
        String userId,
        
        @ToolParam(description = "조회할 IP 주소", required = false) 
        String ipAddress,
        
        @ToolParam(description = "조회 시작 날짜 (ISO-8601 형식, 예: 2024-01-01T00:00:00)", required = false) 
        String dateFrom,
        
        @ToolParam(description = "조회 종료 날짜 (ISO-8601 형식, 예: 2024-01-31T23:59:59)", required = false) 
        String dateTo,
        
        @ToolParam(description = "최대 결과 개수 (기본값: 100, 최대: 1000)", required = false) 
        Integer limit
    ) {
        long startTime = System.currentTimeMillis();
        
        log.info("감사 로그 조회 - User: {}, IP: {}, From: {}, To: {}, Limit: {}", 
            userId, ipAddress, dateFrom, dateTo, limit);
        
        try {
            // 입력 검증
            if (!StringUtils.hasText(userId) && !StringUtils.hasText(ipAddress)) {
                log.warn("No search criteria provided");
                return Response.builder()
                    .success(false)
                    .message("At least one search criteria (userId or ipAddress) is required")
                    .logs(Collections.emptyList())
                    .totalCount(0)
                    .build();
            }
            
            // limit 검증 및 기본값 설정
            int effectiveLimit = (limit != null && limit > 0 && limit <= 1000) ? limit : 100;
            
            // 로그 조회
            List<AuditLogService.AuditLog> logs;
            String searchCriteria;
            
            if (StringUtils.hasText(userId)) {
                logs = auditLogService.findByUserId(userId, effectiveLimit);
                searchCriteria = "userId=" + userId;
            } else if (StringUtils.hasText(ipAddress)) {
                logs = auditLogService.findByIpAddress(ipAddress, effectiveLimit);
                searchCriteria = "ipAddress=" + ipAddress;
            } else {
                logs = Collections.emptyList();
                searchCriteria = "none";
            }
            
            log.info("Found {} audit logs for criteria: {}", logs.size(), searchCriteria);
            
            // 위협 분석
            String threatLevel = analyzeThreatLevel(logs);
            ThreatAnalysis analysis = performDetailedAnalysis(logs);
            
            // 감사 로깅
            SecurityToolUtils.auditLog(
                "audit_log_query",
                "query",
                "SOAR-System",
                String.format("Criteria=%s, Results=%d, ThreatLevel=%s", 
                    searchCriteria, logs.size(), threatLevel),
                "SUCCESS"
            );
            
            // 메트릭 기록
            SecurityToolUtils.recordMetric("audit_log_query", "execution_count", 1);
            SecurityToolUtils.recordMetric("audit_log_query", "results_count", logs.size());
            SecurityToolUtils.recordMetric("audit_log_query", "execution_time_ms", 
                System.currentTimeMillis() - startTime);
            
            return Response.builder()
                .success(true)
                .message(String.format("Successfully retrieved %d audit logs", logs.size()))
                .logs(logs)
                .totalCount(logs.size())
                .threatLevel(threatLevel)
                .threatAnalysis(analysis)
                .build();
                
        } catch (Exception e) {
            log.error("Failed to query audit logs", e);
            
            // 에러 메트릭
            SecurityToolUtils.recordMetric("audit_log_query", "error_count", 1);
            
            return Response.builder()
                .success(false)
                .message("Failed to query audit logs: " + e.getMessage())
                .logs(Collections.emptyList())
                .totalCount(0)
                .build();
        }
    }
    
    /**
     * 위협 레벨 분석
     */
    private String analyzeThreatLevel(List<AuditLogService.AuditLog> logs) {
        if (logs.isEmpty()) {
            return "NONE";
        }
        
        // 실패한 시도 카운트
        long failedAttempts = logs.stream()
            .filter(log -> "FAILURE".equals(log.getResult()))
            .count();
        
        // 에러 카운트
        long errorCount = logs.stream()
            .filter(log -> log.getErrorMessage() != null)
            .count();
        
        // 위협 레벨 계산
        if (failedAttempts > 10 || errorCount > 5) {
            return "HIGH";
        } else if (failedAttempts > 5 || errorCount > 2) {
            return "MEDIUM";
        } else if (failedAttempts > 0 || errorCount > 0) {
            return "LOW";
        }
        
        return "NONE";
    }
    
    /**
     * 상세 위협 분석
     */
    private ThreatAnalysis performDetailedAnalysis(List<AuditLogService.AuditLog> logs) {
        if (logs.isEmpty()) {
            return ThreatAnalysis.builder()
                .failedLoginAttempts(0)
                .suspiciousActivities(0)
                .privilegeEscalations(0)
                .dataExfiltrationAttempts(0)
                .riskScore(0.0)
                .build();
        }
        
        // 각종 위협 지표 계산
        long failedLogins = logs.stream()
            .filter(log -> "LOGIN".equals(log.getAction()) && "FAILURE".equals(log.getResult()))
            .count();
            
        long suspiciousActivities = logs.stream()
            .filter(log -> log.getErrorMessage() != null && 
                          (log.getErrorMessage().contains("suspicious") || 
                           log.getErrorMessage().contains("anomaly")))
            .count();
            
        long privilegeEscalations = logs.stream()
            .filter(log -> log.getAction() != null && 
                          (log.getAction().contains("PRIVILEGE") || 
                           log.getAction().contains("ESCALATION")))
            .count();
            
        long dataExfiltrations = logs.stream()
            .filter(log -> log.getAction() != null && 
                          (log.getAction().contains("EXPORT") || 
                           log.getAction().contains("DOWNLOAD")))
            .count();
        
        // 리스크 점수 계산 (0.0 ~ 1.0)
        double riskScore = Math.min(1.0, 
            (failedLogins * 0.1 + 
             suspiciousActivities * 0.3 + 
             privilegeEscalations * 0.4 + 
             dataExfiltrations * 0.2) / 10.0);
        
        return ThreatAnalysis.builder()
            .failedLoginAttempts(failedLogins)
            .suspiciousActivities(suspiciousActivities)
            .privilegeEscalations(privilegeEscalations)
            .dataExfiltrationAttempts(dataExfiltrations)
            .riskScore(riskScore)
            .build();
    }

    /**
     * Response DTO
     */
    @Data
    @Builder
    public static class Response {
        private boolean success;
        private String message;
        private List<AuditLogService.AuditLog> logs;
        private int totalCount;
        private String threatLevel;
        private ThreatAnalysis threatAnalysis;
    }
    
    /**
     * 위협 분석 결과 DTO
     */
    @Data
    @Builder
    public static class ThreatAnalysis {
        private long failedLoginAttempts;
        private long suspiciousActivities;
        private long privilegeEscalations;
        private long dataExfiltrationAttempts;
        private double riskScore;
    }
}