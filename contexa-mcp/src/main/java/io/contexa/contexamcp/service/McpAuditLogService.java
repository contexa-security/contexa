package io.contexa.contexamcp.service;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class McpAuditLogService {
    
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final RowMapper<AuditLog> auditLogRowMapper = new AuditLogRowMapper();

    @Transactional
    public void saveAuditLog(AuditLog auditLog) {
        String sql = """
            INSERT INTO audit_log (
                timestamp, principal_name, resource_identifier, action, 
                decision, reason, client_ip, details, outcome, 
                resource_uri, parameters, session_id, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

        Instant timestamp = auditLog.getTimestamp() != null ? auditLog.getTimestamp() : Instant.now();
        String principalName = hasText(auditLog.getUsername()) ? auditLog.getUsername() : auditLog.getUserId();
        if (!hasText(principalName)) {
            principalName = "SYSTEM";
        }
        String resourceIdentifier = hasText(auditLog.getResourceId()) ? auditLog.getResourceId() : "unknown";
        String outcome = hasText(auditLog.getResult()) ? auditLog.getResult() : "UNKNOWN";
        String decision = hasText(auditLog.getDecision()) ? auditLog.getDecision() : "ALLOW";
        String reason = hasText(auditLog.getErrorMessage()) ? auditLog.getErrorMessage() : null;
        String metadataJson = serializeMetadata(auditLog.getMetadata());
        
        jdbcTemplate.update(sql,
            Timestamp.from(timestamp),
            principalName,
            resourceIdentifier,
            auditLog.getAction(),
            decision,
            reason,
            auditLog.getIpAddress(),
            reason,
            outcome,
            auditLog.getResourceType(),
            metadataJson,
            auditLog.getSessionId(),
            outcome
        );
        
            }

    public List<AuditLog> findByUserId(String userId, int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE principal_name = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, auditLogRowMapper, userId, limit);
    }

    public List<AuditLog> findByTimeRange(Instant startTime, Instant endTime, int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE timestamp BETWEEN ? AND ? 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, auditLogRowMapper,
            Timestamp.from(startTime), Timestamp.from(endTime), limit);
    }

    public List<AuditLog> findByIpAddress(String ipAddress, int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE client_ip = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, auditLogRowMapper, ipAddress, limit);
    }

    public List<AuditLog> findFailedActions(int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE outcome = 'FAILURE' OR status = 'FAILURE' 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, auditLogRowMapper, limit);
    }

    public List<AuditLog> findSecurityEvents(int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE action IN ('LOGIN_FAILED', 'UNAUTHORIZED_ACCESS', 'PERMISSION_DENIED', 
                            'SUSPICIOUS_ACTIVITY', 'SECURITY_ALERT', 'PASSWORD_CHANGE_FAILED')
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, auditLogRowMapper, limit);
    }

    public List<Map<String, Object>> getUserActionStatistics(Instant startTime, Instant endTime) {
        String sql = """
            SELECT principal_name, action, COUNT(*) as count 
            FROM audit_log 
            WHERE timestamp BETWEEN ? AND ? 
            GROUP BY principal_name, action 
            ORDER BY count DESC
            """;
        
        return jdbcTemplate.queryForList(sql, 
            Timestamp.from(startTime), Timestamp.from(endTime));
    }

    public List<Map<String, Object>> getHourlyActionStatistics(Instant startTime, Instant endTime) {
        String sql = """
            SELECT DATE_TRUNC('hour', timestamp) as hour, 
                   COUNT(*) as total_actions,
                   SUM(CASE WHEN outcome = 'SUCCESS' OR status = 'SUCCESS' THEN 1 ELSE 0 END) as successful,
                   SUM(CASE WHEN outcome = 'FAILURE' OR status = 'FAILURE' THEN 1 ELSE 0 END) as failed
            FROM audit_log 
            WHERE timestamp BETWEEN ? AND ? 
            GROUP BY hour 
            ORDER BY hour DESC
            """;
        
        return jdbcTemplate.queryForList(sql, 
            Timestamp.from(startTime), Timestamp.from(endTime));
    }

    public List<AuditLog> findByCombinedFilters(String userId, String ipAddress,
                                                Instant startTime, Instant endTime, int limit) {
        StringBuilder sql = new StringBuilder("SELECT * FROM audit_log WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (userId != null && !userId.isBlank()) {
            sql.append(" AND principal_name = ?");
            params.add(userId);
        }
        if (ipAddress != null && !ipAddress.isBlank()) {
            sql.append(" AND client_ip = ?");
            params.add(ipAddress);
        }
        if (startTime != null) {
            sql.append(" AND timestamp >= ?");
            params.add(Timestamp.from(startTime));
        }
        if (endTime != null) {
            sql.append(" AND timestamp <= ?");
            params.add(Timestamp.from(endTime));
        }

        sql.append(" ORDER BY timestamp DESC LIMIT ?");
        params.add(limit);

        return jdbcTemplate.query(sql.toString(), auditLogRowMapper, params.toArray());
    }

    public void auditToolExecution(String toolName, String userId, String action,
                                  boolean success, Map<String, Object> metadata) {
        String executedAction = hasText(action) ? action : "TOOL_EXECUTION";
        AuditLog auditLog = AuditLog.builder()
            .timestamp(Instant.now())
            .userId(userId)
            .username(userId)  
            .action(executedAction)
            .resourceType("TOOL")
            .resourceId(toolName)
            .result(success ? "SUCCESS" : "FAILURE")
            .decision(success ? "ALLOW" : "DENY")
            .metadata(metadata)
            .build();
        
        saveAuditLog(auditLog);
    }

    private class AuditLogRowMapper implements RowMapper<AuditLog> {
        @Override
        public AuditLog mapRow(ResultSet rs, int rowNum) throws SQLException {
            Timestamp timestamp = rs.getTimestamp("timestamp");
            return AuditLog.builder()
                .id(rs.getLong("id"))
                .timestamp(timestamp != null ? timestamp.toInstant() : null)
                .userId(rs.getString("principal_name"))
                .username(rs.getString("principal_name"))
                .action(rs.getString("action"))
                .resourceType(rs.getString("resource_uri"))
                .resourceId(rs.getString("resource_identifier"))
                .ipAddress(rs.getString("client_ip"))
                .userAgent(null)
                .decision(rs.getString("decision"))
                .result(rs.getString("outcome"))
                .errorMessage(rs.getString("reason"))
                .sessionId(rs.getString("session_id"))
                .metadata(parseJsonMetadata(rs.getString("parameters")))
                .build();
        }
        
        private Map<String, Object> parseJsonMetadata(String json) {
             
            if (json == null || json.isEmpty() || "{}".equals(json)) {
                return Map.of();
            }
            try {
                return objectMapper.readValue(json, Map.class);
            } catch (Exception e) {
                return Map.of("raw", json);
            }
        }
    }

    @Data
    @Builder
    public static class AuditLog {
        private Long id;
        private Instant timestamp;
        private String userId;
        private String username;
        private String action;
        private String resourceType;
        private String resourceId;
        private String ipAddress;
        private String userAgent;
        private String result;  
        private String errorMessage;
        private String sessionId;
        private Map<String, Object> metadata;
        private String decision;
    }

    private String serializeMetadata(Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return "{}";
        }
        try {
            return objectMapper.writeValueAsString(metadata);
        } catch (Exception e) {
            log.error("Failed to serialize metadata to JSON", e);
            return "{}";
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
