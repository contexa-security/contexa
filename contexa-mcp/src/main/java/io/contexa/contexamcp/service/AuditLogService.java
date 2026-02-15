package io.contexa.contexamcp.service;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogService {
    
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    @Transactional
    public void saveAuditLog(AuditLog auditLog) {
        String sql = """
            INSERT INTO audit_log (
                id, timestamp, principal_name, resource_identifier, action, 
                decision, reason, client_ip, details, outcome, 
                resource_uri, parameters, session_id, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?)
            """;
        
        jdbcTemplate.update(sql,
            UUID.randomUUID(),
            Timestamp.from(auditLog.getTimestamp()),
            auditLog.getUsername() != null ? auditLog.getUsername() : auditLog.getUserId(),
            auditLog.getResourceId(),
            auditLog.getAction(),
            auditLog.getDecision() != null ? auditLog.getDecision() : "ALLOW",
            auditLog.getErrorMessage() != null ? auditLog.getErrorMessage() : "N/A",
            auditLog.getIpAddress(),
            auditLog.getErrorMessage(),
            auditLog.getResult(),
            auditLog.getResourceType(),
            serializeMetadata(auditLog.getMetadata()),
            auditLog.getSessionId(),
            auditLog.getResult()
        );
        
            }

    public List<AuditLog> findByUserId(String userId, int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE principal_name = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, new AuditLogRowMapper(), userId, limit);
    }

    public List<AuditLog> findByAction(String action, int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE action = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, new AuditLogRowMapper(), action, limit);
    }

    public List<AuditLog> findByResource(String resourceType, String resourceId, int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE resource_uri = ? AND resource_identifier = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, new AuditLogRowMapper(), resourceType, resourceId, limit);
    }

    public List<AuditLog> findByTimeRange(Instant startTime, Instant endTime, int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE timestamp BETWEEN ? AND ? 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, new AuditLogRowMapper(), 
            Timestamp.from(startTime), Timestamp.from(endTime), limit);
    }

    public List<AuditLog> findByIpAddress(String ipAddress, int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE client_ip = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, new AuditLogRowMapper(), ipAddress, limit);
    }

    public List<AuditLog> findFailedActions(int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE outcome = 'FAILURE' OR status = 'FAILURE' 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, new AuditLogRowMapper(), limit);
    }

    public List<AuditLog> findSecurityEvents(int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE action IN ('LOGIN_FAILED', 'UNAUTHORIZED_ACCESS', 'PERMISSION_DENIED', 
                            'SUSPICIOUS_ACTIVITY', 'SECURITY_ALERT', 'PASSWORD_CHANGE_FAILED')
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, new AuditLogRowMapper(), limit);
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

        return jdbcTemplate.query(sql.toString(), new AuditLogRowMapper(), params.toArray());
    }

    public void auditToolExecution(String toolName, String userId, String action,
                                  boolean success, Map<String, Object> metadata) {
        AuditLog auditLog = AuditLog.builder()
            .timestamp(Instant.now())
            .userId(userId)
            .username(userId)  
            .action("TOOL_EXECUTION")
            .resourceType("TOOL")
            .resourceId(toolName)
            .result(success ? "SUCCESS" : "FAILURE")
            .decision(success ? "ALLOW" : "DENY")
            .metadata(metadata)
            .build();
        
        saveAuditLog(auditLog);
    }

    private static class AuditLogRowMapper implements RowMapper<AuditLog> {
        @Override
        public AuditLog mapRow(ResultSet rs, int rowNum) throws SQLException {
            return AuditLog.builder()
                .id(rs.getObject("id", UUID.class))
                .timestamp(rs.getTimestamp("timestamp").toInstant())
                .userId(rs.getString("principal_name"))
                .username(rs.getString("principal_name"))
                .action(rs.getString("action"))
                .resourceType(rs.getString("resource_uri"))
                .resourceId(rs.getString("resource_identifier"))
                .ipAddress(rs.getString("client_ip"))
                .userAgent(null)  
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
            
            return Map.of("raw", json);
        }
    }

    @Data
    @Builder
    public static class AuditLog {
        private UUID id;
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
}