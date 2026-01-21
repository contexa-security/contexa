package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;

@Slf4j
public class AdminOverrideRepository {

    private final RedisTemplate<String, Object> redisTemplate;

    public AdminOverrideRepository(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    private static final String KEY_PREFIX = "security:admin:override:";
    private static final String PENDING_PREFIX = "security:admin:override:pending:";
    private static final String USER_INDEX_PREFIX = "security:admin:override:user:";
    private static final String EVENT_PREFIX = "security:admin:override:event:";
    private static final Duration TTL = Duration.ofDays(30);
    private static final Duration PENDING_TTL = Duration.ofDays(7);

    public void save(AdminOverride override) {
        if (override == null || override.getRequestId() == null) {
            log.warn("[AdminOverrideRepository] null override 또는 requestId로 저장 시도");
            return;
        }

        String key = KEY_PREFIX + override.getRequestId();
        Map<String, Object> data = toMap(override);

        try {
            redisTemplate.opsForHash().putAll(key, data);
            redisTemplate.expire(key, TTL);

            if (override.getUserId() != null) {
                String userIndexKey = USER_INDEX_PREFIX + override.getUserId();
                redisTemplate.opsForSet().add(userIndexKey, override.getRequestId());
                redisTemplate.expire(userIndexKey, TTL);
            }

        } catch (Exception e) {
            log.error("[AdminOverrideRepository] Redis 저장 실패: requestId={}",
                    override.getRequestId(), e);
        }
    }

    public void savePending(String requestId, String userId, Map<String, Object> analysisData) {
        if (requestId == null) {
            log.warn("[AdminOverrideRepository] null requestId로 pending 저장 시도");
            return;
        }

        String key = PENDING_PREFIX + requestId;
        Map<String, Object> data = new HashMap<>();

        if (analysisData != null) {
            data.putAll(analysisData);
        }
        data.put("userId", userId != null ? userId : "unknown");
        data.put("requestId", requestId);
        data.put("timestamp", Instant.now().toString());
        data.put("status", "PENDING");

        try {
            redisTemplate.opsForHash().putAll(key, data);
            redisTemplate.expire(key, PENDING_TTL);

        } catch (Exception e) {
            log.error("[AdminOverrideRepository] pending 저장 실패: requestId={}", requestId, e);
        }
    }

    public void saveSecurityEvent(String requestId, SecurityEvent event) {
        if (requestId == null || event == null) {
            log.warn("[AdminOverrideRepository] null requestId 또는 event로 saveSecurityEvent 시도");
            return;
        }

        String key = EVENT_PREFIX + requestId;
        Map<String, Object> data = securityEventToMap(event);

        try {
            redisTemplate.opsForHash().putAll(key, data);
            redisTemplate.expire(key, PENDING_TTL);

        } catch (Exception e) {
            log.error("[AdminOverrideRepository] SecurityEvent 저장 실패: requestId={}", requestId, e);
        }
    }

    public Optional<SecurityEvent> findSecurityEvent(String requestId) {
        if (requestId == null) {
            return Optional.empty();
        }

        String key = EVENT_PREFIX + requestId;

        try {
            Map<Object, Object> data = redisTemplate.opsForHash().entries(key);

            if (data.isEmpty()) {
                return Optional.empty();
            }

            return Optional.of(securityEventFromMap(data));

        } catch (Exception e) {
            log.error("[AdminOverrideRepository] SecurityEvent 조회 실패: requestId={}", requestId, e);
            return Optional.empty();
        }
    }

    public void deleteSecurityEvent(String requestId) {
        if (requestId == null) {
            return;
        }

        String key = EVENT_PREFIX + requestId;

        try {
            Boolean deleted = redisTemplate.delete(key);
            if (Boolean.TRUE.equals(deleted)) {
            }

        } catch (Exception e) {
            log.error("[AdminOverrideRepository] SecurityEvent 삭제 실패: requestId={}", requestId, e);
        }
    }

    public Optional<AdminOverride> findByRequestId(String requestId) {
        if (requestId == null) {
            return Optional.empty();
        }

        String key = KEY_PREFIX + requestId;

        try {
            Map<Object, Object> data = redisTemplate.opsForHash().entries(key);

            if (data.isEmpty()) {
                return Optional.empty();
            }

            return Optional.of(fromMap(data));

        } catch (Exception e) {
            log.error("[AdminOverrideRepository] 조회 실패: requestId={}", requestId, e);
            return Optional.empty();
        }
    }

    public Optional<Map<Object, Object>> findPending(String requestId) {
        if (requestId == null) {
            return Optional.empty();
        }

        String key = PENDING_PREFIX + requestId;

        try {
            Map<Object, Object> data = redisTemplate.opsForHash().entries(key);
            return data.isEmpty() ? Optional.empty() : Optional.of(data);

        } catch (Exception e) {
            log.error("[AdminOverrideRepository] pending 조회 실패: requestId={}", requestId, e);
            return Optional.empty();
        }
    }

    public void deletePending(String requestId) {
        if (requestId == null) {
            return;
        }

        String key = PENDING_PREFIX + requestId;

        try {
            Boolean deleted = redisTemplate.delete(key);
            if (Boolean.TRUE.equals(deleted)) {
            }

        } catch (Exception e) {
            log.error("[AdminOverrideRepository] pending 삭제 실패: requestId={}", requestId, e);
        }
    }

    public List<AdminOverride> findByUserId(String userId) {
        if (userId == null) {
            return Collections.emptyList();
        }

        String userIndexKey = USER_INDEX_PREFIX + userId;
        List<AdminOverride> results = new ArrayList<>();

        try {
            Set<Object> requestIds = redisTemplate.opsForSet().members(userIndexKey);

            if (requestIds == null || requestIds.isEmpty()) {
                return Collections.emptyList();
            }

            for (Object reqId : requestIds) {
                findByRequestId((String) reqId).ifPresent(results::add);
            }

            return results;

        } catch (Exception e) {
            log.error("[AdminOverrideRepository] 사용자별 조회 실패: userId={}", userId, e);
            return Collections.emptyList();
        }
    }

    private Map<String, Object> toMap(AdminOverride override) {
        Map<String, Object> map = new HashMap<>();
        map.put("overrideId", override.getOverrideId());
        map.put("requestId", override.getRequestId());
        map.put("userId", override.getUserId());
        map.put("adminId", override.getAdminId());
        map.put("timestamp", override.getTimestamp() != null ? override.getTimestamp().toString() : null);
        map.put("originalAction", override.getOriginalAction());
        map.put("overriddenAction", override.getOverriddenAction());
        map.put("reason", override.getReason());
        map.put("approved", String.valueOf(override.isApproved()));
        map.put("baselineUpdateAllowed", String.valueOf(override.isBaselineUpdateAllowed()));
        map.put("originalRiskScore", String.valueOf(override.getOriginalRiskScore()));
        map.put("originalConfidence", String.valueOf(override.getOriginalConfidence()));
        return map;
    }

    private AdminOverride fromMap(Map<Object, Object> data) {
        return AdminOverride.builder()
                .overrideId(getStringFromMap(data, "overrideId"))
                .requestId(getStringFromMap(data, "requestId"))
                .userId(getStringFromMap(data, "userId"))
                .adminId(getStringFromMap(data, "adminId"))
                .timestamp(parseInstant(getStringFromMap(data, "timestamp")))
                .originalAction(getStringFromMap(data, "originalAction"))
                .overriddenAction(getStringFromMap(data, "overriddenAction"))
                .reason(getStringFromMap(data, "reason"))
                .approved(parseBoolean(getStringFromMap(data, "approved")))
                .baselineUpdateAllowed(parseBoolean(getStringFromMap(data, "baselineUpdateAllowed")))
                .originalRiskScore(parseDouble(getStringFromMap(data, "originalRiskScore")))
                .originalConfidence(parseDouble(getStringFromMap(data, "originalConfidence")))
                .build();
    }

    private String getStringFromMap(Map<Object, Object> data, String key) {
        Object value = data.get(key);
        return value != null ? value.toString() : null;
    }

    private Instant parseInstant(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (Exception e) {
            log.warn("[AdminOverrideRepository] Instant 파싱 실패: {}", value);
            return null;
        }
    }

    private boolean parseBoolean(String value) {
        return "true".equalsIgnoreCase(value);
    }

    private double parseDouble(String value) {
        if (value == null || value.isEmpty()) {
            return 0.0;
        }
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException e) {
            log.warn("[AdminOverrideRepository] double 파싱 실패: {}", value);
            return 0.0;
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> securityEventToMap(SecurityEvent event) {
        Map<String, Object> map = new HashMap<>();
        map.put("eventId", event.getEventId());
        map.put("source", event.getSource() != null ? event.getSource().name() : null);
        map.put("severity", event.getSeverity() != null ? event.getSeverity().name() : null);
        map.put("userId", event.getUserId());
        map.put("sourceIp", event.getSourceIp());
        map.put("sessionId", event.getSessionId());
        map.put("userAgent", event.getUserAgent());
        map.put("userName", event.getUserName());
        map.put("protocol", event.getProtocol());
        map.put("blocked", String.valueOf(event.isBlocked()));
        map.put("description", event.getDescription());
        map.put("timestamp", event.getTimestamp() != null ? event.getTimestamp().toString() : null);

        if (event.getMetadata() != null && !event.getMetadata().isEmpty()) {
            try {
                StringBuilder sb = new StringBuilder("{");
                boolean first = true;
                for (Map.Entry<String, Object> entry : event.getMetadata().entrySet()) {
                    if (!first) sb.append(",");
                    sb.append("\"").append(entry.getKey()).append("\":\"")
                            .append(entry.getValue() != null ? entry.getValue().toString() : "").append("\"");
                    first = false;
                }
                sb.append("}");
                map.put("metadata", sb.toString());
            } catch (Exception e) {
                log.warn("[AdminOverrideRepository] metadata 변환 실패: {}", e.getMessage());
            }
        }

        return map;
    }

    private SecurityEvent securityEventFromMap(Map<Object, Object> data) {
        SecurityEvent.SecurityEventBuilder builder = SecurityEvent.builder()
                .eventId(getStringFromMap(data, "eventId"))
                .userId(getStringFromMap(data, "userId"))
                .sourceIp(getStringFromMap(data, "sourceIp"))
                .sessionId(getStringFromMap(data, "sessionId"))
                .userAgent(getStringFromMap(data, "userAgent"))
                .userName(getStringFromMap(data, "userName"))
                .protocol(getStringFromMap(data, "protocol"))
                .blocked(parseBoolean(getStringFromMap(data, "blocked")))
                .description(getStringFromMap(data, "description"));

        String sourceStr = getStringFromMap(data, "source");
        if (sourceStr != null && !sourceStr.isEmpty()) {
            try {
                builder.source(SecurityEvent.EventSource.valueOf(sourceStr));
            } catch (IllegalArgumentException e) {
                log.warn("[AdminOverrideRepository] EventSource 파싱 실패: {}", sourceStr);
            }
        }

        String severityStr = getStringFromMap(data, "severity");
        if (severityStr != null && !severityStr.isEmpty()) {
            try {
                builder.severity(SecurityEvent.Severity.valueOf(severityStr));
            } catch (IllegalArgumentException e) {
                log.warn("[AdminOverrideRepository] Severity 파싱 실패: {}", severityStr);
            }
        }

        String timestampStr = getStringFromMap(data, "timestamp");
        if (timestampStr != null && !timestampStr.isEmpty()) {
            try {
                builder.timestamp(LocalDateTime.parse(timestampStr));
            } catch (Exception e) {
                log.warn("[AdminOverrideRepository] LocalDateTime 파싱 실패: {}", timestampStr);
            }
        }

        String metadataStr = getStringFromMap(data, "metadata");
        if (metadataStr != null && !metadataStr.isEmpty() && metadataStr.startsWith("{")) {
            try {
                Map<String, Object> metadata = new HashMap<>();
                String content = metadataStr.substring(1, metadataStr.length() - 1);
                if (!content.isEmpty()) {
                    String[] pairs = content.split(",");
                    for (String pair : pairs) {
                        String[] kv = pair.split(":", 2);
                        if (kv.length == 2) {
                            String key = kv[0].trim().replace("\"", "");
                            String value = kv[1].trim().replace("\"", "");
                            metadata.put(key, value);
                        }
                    }
                }
                builder.metadata(metadata);
            } catch (Exception e) {
                log.warn("[AdminOverrideRepository] metadata 파싱 실패: {}", e.getMessage());
            }
        }

        return builder.build();
    }
}
