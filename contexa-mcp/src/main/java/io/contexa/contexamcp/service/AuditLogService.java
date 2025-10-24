package io.contexa.contexamcp.service;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Audit Log Service
 * 감사 로그 조회 및 저장 서비스
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogService {
    
    private final JdbcTemplate jdbcTemplate;
    
    /**
     * 감사 로그 저장
     */
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
            "ALLOW",  // 기본값
            auditLog.getErrorMessage() != null ? auditLog.getErrorMessage() : "N/A",
            auditLog.getIpAddress(),
            auditLog.getErrorMessage(),
            auditLog.getResult(),
            auditLog.getResourceType(),
            auditLog.getMetadata() != null ? auditLog.getMetadata().toString() : "{}",
            auditLog.getSessionId(),
            auditLog.getResult()
        );
        
        log.debug("Audit log saved: {} - {} by {}", 
            auditLog.getAction(), auditLog.getResourceType(), auditLog.getUserId());
    }
    
    /**
     * 감사 로그 조회 - 사용자별
     */
    public List<AuditLog> findByUserId(String userId, int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE principal_name = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, new AuditLogRowMapper(), userId, limit);
    }
    
    /**
     * 감사 로그 조회 - 액션별
     */
    public List<AuditLog> findByAction(String action, int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE action = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, new AuditLogRowMapper(), action, limit);
    }
    
    /**
     * 감사 로그 조회 - 리소스별
     */
    public List<AuditLog> findByResource(String resourceType, String resourceId, int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE resource_uri = ? AND resource_identifier = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, new AuditLogRowMapper(), resourceType, resourceId, limit);
    }
    
    /**
     * 감사 로그 조회 - 기간별
     */
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
    
    /**
     * 감사 로그 조회 - IP 주소별
     */
    public List<AuditLog> findByIpAddress(String ipAddress, int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE client_ip = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, new AuditLogRowMapper(), ipAddress, limit);
    }
    
    /**
     * 실패한 작업 조회
     */
    public List<AuditLog> findFailedActions(int limit) {
        String sql = """
            SELECT * FROM audit_log 
            WHERE outcome = 'FAILURE' OR status = 'FAILURE' 
            ORDER BY timestamp DESC 
            LIMIT ?
            """;
        
        return jdbcTemplate.query(sql, new AuditLogRowMapper(), limit);
    }
    
    /**
     * 보안 이벤트 조회 (특정 액션들)
     */
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
    
    /**
     * 통계 조회 - 사용자별 액션 수
     */
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
    
    /**
     * 통계 조회 - 시간대별 액션 수
     */
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
    
    /**
     * 도구 실행 감사 로그 생성
     */
    public void auditToolExecution(String toolName, String userId, String action, 
                                  boolean success, Map<String, Object> metadata) {
        AuditLog auditLog = AuditLog.builder()
            .timestamp(Instant.now())
            .userId(userId)
            .username(userId)  // 실제로는 사용자 서비스에서 조회
            .action("TOOL_EXECUTION")
            .resourceType("TOOL")
            .resourceId(toolName)
            .result(success ? "SUCCESS" : "FAILURE")
            .metadata(metadata)
            .build();
        
        saveAuditLog(auditLog);
    }
    
    /**
     * Audit Log RowMapper
     */
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
                .userAgent(null)  // 컴럼에 없음
                .result(rs.getString("outcome"))
                .errorMessage(rs.getString("reason"))
                .sessionId(rs.getString("session_id"))
                .metadata(parseJsonMetadata(rs.getString("parameters")))
                .build();
        }
        
        private Map<String, Object> parseJsonMetadata(String json) {
            // 간단한 구현 - 실제로는 Jackson을 사용
            if (json == null || json.isEmpty() || "{}".equals(json)) {
                return Map.of();
            }
            // TODO: Jackson ObjectMapper로 파싱
            return Map.of("raw", json);
        }
    }
    
    /**
     * Audit Log Entity
     */
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
        private String result;  // SUCCESS, FAILURE
        private String errorMessage;
        private String sessionId;
        private Map<String, Object> metadata;
    }
}