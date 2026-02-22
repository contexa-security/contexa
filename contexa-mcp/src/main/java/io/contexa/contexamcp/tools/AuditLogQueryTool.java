package io.contexa.contexamcp.tools;

import io.contexa.contexacommon.annotation.SoarTool;
import io.contexa.contexamcp.service.McpAuditLogService;
import io.contexa.contexamcp.utils.SecurityToolUtils;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.StringJoiner;

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

    private final McpAuditLogService mcpAuditLogService;

    @Tool(
            name = "audit_log_query",
            description = """
            Query audit logs to analyze security threats.
            Search logs by user ID, IP address, and date range.
            Automatically analyzes and provides threat levels.
            """
    )

    public Response queryAuditLogs(
            @ToolParam(description = "User ID to query", required = false)
            String userId,

            @ToolParam(description = "IP address to query", required = false)
            String ipAddress,

            @ToolParam(description = "Start date (ISO-8601 format, e.g., 2024-01-01T00:00:00)", required = false)
            String dateFrom,

            @ToolParam(description = "End date (ISO-8601 format, e.g., 2024-01-31T23:59:59)", required = false)
            String dateTo,

            @ToolParam(description = "Max result count (default: 100, max: 1000)", required = false)
            Integer limit
    ) {
        long operationStart = System.currentTimeMillis();

        try {

            if (!StringUtils.hasText(userId) && !StringUtils.hasText(ipAddress)
                    && !StringUtils.hasText(dateFrom) && !StringUtils.hasText(dateTo)) {
                log.error("No search criteria provided");
                return Response.builder()
                        .success(false)
                        .message("At least one search criteria (userId, ipAddress, or date range) is required")
                        .logs(Collections.emptyList())
                        .totalCount(0)
                        .build();
            }

            int effectiveLimit = (limit != null && limit > 0 && limit <= 1000) ? limit : 100;

            Instant startTime = StringUtils.hasText(dateFrom) ? Instant.parse(dateFrom) : null;
            Instant endTime = StringUtils.hasText(dateTo) ? Instant.parse(dateTo) : null;

            List<McpAuditLogService.AuditLog> logs = mcpAuditLogService.findByCombinedFilters(
                    userId, ipAddress, startTime, endTime, effectiveLimit);

            StringJoiner criteriaJoiner = new StringJoiner(", ");
            if (StringUtils.hasText(userId)) criteriaJoiner.add("userId=" + userId);
            if (StringUtils.hasText(ipAddress)) criteriaJoiner.add("ipAddress=" + ipAddress);
            if (startTime != null) criteriaJoiner.add("from=" + dateFrom);
            if (endTime != null) criteriaJoiner.add("to=" + dateTo);
            String searchCriteria = criteriaJoiner.toString();

            String threatLevel = analyzeThreatLevel(logs);
            ThreatAnalysis analysis = performDetailedAnalysis(logs);

            SecurityToolUtils.auditLog(
                    "audit_log_query",
                    "query",
                    "SOAR-System",
                    String.format("Criteria=%s, Results=%d, ThreatLevel=%s",
                            searchCriteria, logs.size(), threatLevel),
                    "SUCCESS"
            );

            SecurityToolUtils.recordMetric("audit_log_query", "execution_count", 1);
            SecurityToolUtils.recordMetric("audit_log_query", "results_count", logs.size());
            SecurityToolUtils.recordMetric("audit_log_query", "execution_time_ms",
                    System.currentTimeMillis() - operationStart);

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

            SecurityToolUtils.recordMetric("audit_log_query", "error_count", 1);

            return Response.builder()
                    .success(false)
                    .message("Failed to query audit logs: " + e.getMessage())
                    .logs(Collections.emptyList())
                    .totalCount(0)
                    .build();
        }
    }

    private String analyzeThreatLevel(List<McpAuditLogService.AuditLog> logs) {
        if (logs.isEmpty()) {
            return "NONE";
        }

        long failedAttempts = logs.stream()
                .filter(log -> "FAILURE".equals(log.getResult()))
                .count();

        long errorCount = logs.stream()
                .filter(log -> log.getErrorMessage() != null)
                .count();

        if (failedAttempts > 10 || errorCount > 5) {
            return "HIGH";
        } else if (failedAttempts > 5 || errorCount > 2) {
            return "MEDIUM";
        } else if (failedAttempts > 0 || errorCount > 0) {
            return "LOW";
        }

        return "NONE";
    }

    private ThreatAnalysis performDetailedAnalysis(List<McpAuditLogService.AuditLog> logs) {
        if (logs.isEmpty()) {
            return ThreatAnalysis.builder()
                    .failedLoginAttempts(0)
                    .suspiciousActivities(0)
                    .privilegeEscalations(0)
                    .dataExfiltrationAttempts(0)
                    .riskScore(0.0)
                    .build();
        }

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

    @Data
    @Builder
    public static class Response {
        private boolean success;
        private String message;
        private List<McpAuditLogService.AuditLog> logs;
        private int totalCount;
        private String threatLevel;
        private ThreatAnalysis threatAnalysis;
    }

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