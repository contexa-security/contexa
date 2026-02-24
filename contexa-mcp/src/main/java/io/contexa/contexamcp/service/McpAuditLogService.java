package io.contexa.contexamcp.service;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

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
        private String result;
        private String errorMessage;
        private String sessionId;
        private Map<String, Object> metadata;
        private String decision;
    }
}
