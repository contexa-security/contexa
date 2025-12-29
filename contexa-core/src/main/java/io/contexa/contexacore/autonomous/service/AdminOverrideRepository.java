package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacore.autonomous.domain.AdminOverride;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * 관리자 개입 Redis 저장소 (AI Native v3.4.0)
 *
 * AI Native 원칙:
 * - BLOCK 판정된 요청에 대한 관리자 검토 이력을 영구 저장
 * - 모든 관리자 개입은 감사 로그로 30일간 보존
 * - 대기 중인 요청은 7일간 유지
 *
 * Redis 스키마:
 * - Key: security:admin:override:{requestId}
 * - TTL: 30일 (감사 목적)
 *
 * 조회 인덱스:
 * - security:admin:override:user:{userId} (사용자별 개입 이력)
 * - security:admin:override:pending:{requestId} (대기 중인 요청)
 *
 * Bean 등록: CoreAutonomousAutoConfiguration에서 @Bean으로 등록
 *
 * @author contexa
 * @since 3.4.0
 */
@Slf4j
public class AdminOverrideRepository {

    private final RedisTemplate<String, Object> redisTemplate;

    public AdminOverrideRepository(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    private static final String KEY_PREFIX = "security:admin:override:";
    private static final String PENDING_PREFIX = "security:admin:override:pending:";
    private static final String USER_INDEX_PREFIX = "security:admin:override:user:";
    private static final Duration TTL = Duration.ofDays(30);
    private static final Duration PENDING_TTL = Duration.ofDays(7);

    /**
     * 관리자 개입 저장
     *
     * 저장 시:
     * 1. 개입 데이터를 Hash로 저장
     * 2. 사용자별 인덱스 업데이트
     * 3. 30일 TTL 설정
     *
     * @param override 관리자 개입 객체
     */
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

            // 사용자별 인덱스 업데이트
            if (override.getUserId() != null) {
                String userIndexKey = USER_INDEX_PREFIX + override.getUserId();
                redisTemplate.opsForSet().add(userIndexKey, override.getRequestId());
                redisTemplate.expire(userIndexKey, TTL);
            }

            log.info("[AdminOverrideRepository][AI Native] 관리자 개입 저장 완료: " +
                    "requestId={}, userId={}, approved={}, baselineUpdateAllowed={}",
                override.getRequestId(), override.getUserId(),
                override.isApproved(), override.isBaselineUpdateAllowed());

        } catch (Exception e) {
            log.error("[AdminOverrideRepository] Redis 저장 실패: requestId={}",
                override.getRequestId(), e);
        }
    }

    /**
     * 대기 중인 요청 저장 (BLOCK 판정 시)
     *
     * LLM이 BLOCK 판정을 내리면 해당 요청을 대기 목록에 저장합니다.
     * 관리자가 검토할 수 있도록 7일간 유지됩니다.
     *
     * @param requestId 요청 ID
     * @param userId 사용자 ID
     * @param analysisData LLM 분석 결과 데이터
     */
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

            log.debug("[AdminOverrideRepository] 대기 요청 저장: requestId={}, userId={}",
                requestId, userId);

        } catch (Exception e) {
            log.error("[AdminOverrideRepository] pending 저장 실패: requestId={}", requestId, e);
        }
    }

    /**
     * 관리자 개입 조회
     *
     * @param requestId 요청 ID
     * @return 관리자 개입 객체 (없으면 Optional.empty())
     */
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

    /**
     * 대기 중인 요청 조회
     *
     * @param requestId 요청 ID
     * @return 대기 중인 요청 데이터 (없으면 Optional.empty())
     */
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

    /**
     * 대기 중인 요청 삭제 (관리자 처리 완료 시)
     *
     * @param requestId 요청 ID
     */
    public void deletePending(String requestId) {
        if (requestId == null) {
            return;
        }

        String key = PENDING_PREFIX + requestId;

        try {
            Boolean deleted = redisTemplate.delete(key);
            if (Boolean.TRUE.equals(deleted)) {
                log.debug("[AdminOverrideRepository] 대기 요청 삭제 완료: requestId={}", requestId);
            }

        } catch (Exception e) {
            log.error("[AdminOverrideRepository] pending 삭제 실패: requestId={}", requestId, e);
        }
    }

    /**
     * 사용자별 관리자 개입 이력 조회
     *
     * @param userId 사용자 ID
     * @return 해당 사용자의 모든 관리자 개입 목록
     */
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

    /**
     * AdminOverride 객체를 Redis Hash용 Map으로 변환
     */
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

    /**
     * Redis Hash Map을 AdminOverride 객체로 변환
     */
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
}
