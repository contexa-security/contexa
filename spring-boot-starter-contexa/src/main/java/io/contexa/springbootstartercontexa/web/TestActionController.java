package io.contexa.springbootstartercontexa.web;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * LLM Action 설정 컨트롤러 (테스트용)
 *
 * 실제 LLM 분석 결과를 시뮬레이션하여 Redis에 저장한다.
 * TrustSecurityExpressionRoot가 이 데이터를 조회하여 SpEL 표현식을 평가한다.
 *
 * Redis 키 구조:
 * - security:hcad:analysis:{userId} (Hash) - HCAD 분석 결과 전체
 *   - action: ALLOW, BLOCK, CHALLENGE, INVESTIGATE, ESCALATE, MONITOR
 *   - riskScore: 0.0 ~ 1.0
 *   - confidence: 0.0 ~ 1.0
 *   - threatLevel: CRITICAL, HIGH, MEDIUM, LOW, INFO
 *   - isAnomaly: true/false
 *   - updatedAt: ISO-8601 타임스탬프
 *
 * - threat_score:{userId} (String) - 위협 점수 (레거시 호환)
 */
@Slf4j
@RestController
@RequestMapping("/api/test-action")
@RequiredArgsConstructor
public class TestActionController {

    private final StringRedisTemplate redisTemplate;

    private static final DateTimeFormatter TIMESTAMP_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    /**
     * 유효한 Action 값 목록
     */
    private static final String[] VALID_ACTIONS = {
        "ALLOW", "BLOCK", "CHALLENGE", "INVESTIGATE", "ESCALATE", "MONITOR"
    };

    /**
     * 현재 사용자의 Action 상태 조회
     *
     * Redis에서 HCAD 분석 결과를 조회하여 반환한다.
     * 데이터가 없으면 PENDING_ANALYSIS 상태로 반환한다.
     *
     * @param user 인증된 사용자
     * @return 현재 Action 상태 정보
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getActionStatus(
            @AuthenticationPrincipal UserDetails user) {

        String userId = extractUserId(user);
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);

        log.info("[Action 상태 조회] userId: {}", userId);

        String hcadKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
        Map<Object, Object> fields = redisTemplate.opsForHash().entries(hcadKey);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("timestamp", timestamp);
        response.put("userId", userId);

        if (fields.isEmpty()) {
            log.info("[Action 상태 조회] 분석 결과 없음 - userId: {}", userId);

            response.put("action", "PENDING_ANALYSIS");
            response.put("riskScore", 0.0);
            response.put("confidence", 0.0);
            response.put("threatLevel", "UNKNOWN");
            response.put("isAnomaly", false);
            response.put("analysisStatus", "NOT_ANALYZED");
            response.put("message", "LLM 분석 결과가 없습니다. Action을 설정하거나 실제 보안 이벤트가 발생할 때까지 PENDING_ANALYSIS 상태입니다.");

            return ResponseEntity.ok(response);
        }

        String action = (String) fields.getOrDefault("action", "PENDING_ANALYSIS");
        String riskScoreStr = (String) fields.getOrDefault("riskScore", "0.0");
        String confidenceStr = (String) fields.getOrDefault("confidence", "0.0");
        String threatLevel = (String) fields.getOrDefault("threatLevel", "UNKNOWN");
        String isAnomalyStr = (String) fields.getOrDefault("isAnomaly", "false");
        String updatedAt = (String) fields.get("updatedAt");

        response.put("action", action);
        response.put("riskScore", Double.parseDouble(riskScoreStr));
        response.put("confidence", Double.parseDouble(confidenceStr));
        response.put("threatLevel", threatLevel);
        response.put("isAnomaly", Boolean.parseBoolean(isAnomalyStr));
        response.put("analysisStatus", "ANALYZED");
        response.put("updatedAt", updatedAt);

        log.info("[Action 상태 조회] 완료 - userId: {}, action: {}, riskScore: {}",
            userId, action, riskScoreStr);

        return ResponseEntity.ok(response);
    }

    /**
     * Action 강제 설정 (테스트용)
     *
     * 실제 LLM 분석 결과를 시뮬레이션하여 Redis에 저장한다.
     * 이 데이터는 TrustSecurityExpressionRoot의 getCurrentAction() 메서드에서 조회된다.
     *
     * @param request Action 설정 요청
     * @param user 인증된 사용자
     * @return 설정 결과
     */
    @PostMapping("/set")
    public ResponseEntity<Map<String, Object>> setAction(
            @RequestBody ActionSetRequest request,
            @AuthenticationPrincipal UserDetails user) {

        String userId = extractUserId(user);
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);

        log.info("[Action 설정] 시작 - userId: {}, action: {}, riskScore: {}, confidence: {}",
            userId, request.action(), request.riskScore(), request.confidence());

        // 유효성 검사
        Map<String, Object> validationResult = validateActionRequest(request);
        if (validationResult != null) {
            log.warn("[Action 설정] 유효성 검사 실패 - {}", validationResult.get("message"));
            return ResponseEntity.badRequest().body(validationResult);
        }

        String hcadKey = ZeroTrustRedisKeys.hcadAnalysis(userId);

        // HCAD 분석 결과 Hash 저장
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("action", request.action().toUpperCase());
        fields.put("riskScore", String.valueOf(request.riskScore()));
        fields.put("confidence", String.valueOf(request.confidence()));
        fields.put("isAnomaly", String.valueOf(request.riskScore() > 0.7));
        fields.put("threatLevel", calculateThreatLevel(request.riskScore()));
        fields.put("threatType", determineThreatType(request.action(), request.riskScore()));
        fields.put("threatEvidence", generateThreatEvidence(request.action(), request.riskScore()));
        fields.put("updatedAt", Instant.now().toString());

        redisTemplate.opsForHash().putAll(hcadKey, fields);

        // Action별 TTL 설정
        long ttlSeconds = calculateTtlByAction(request.action());
        if (ttlSeconds > 0) {
            redisTemplate.expire(hcadKey, ttlSeconds, TimeUnit.SECONDS);
        }

        // threat_score도 설정 (레거시 호환 - Dual-Write)
        String threatKey = ZeroTrustRedisKeys.threatScore(userId);
        redisTemplate.opsForValue().set(threatKey, String.valueOf(request.riskScore()));
        if (ttlSeconds > 0) {
            redisTemplate.expire(threatKey, ttlSeconds, TimeUnit.SECONDS);
        }

        log.info("[Action 설정] 완료 - userId: {}, action: {}, ttl: {}s",
            userId, request.action(), ttlSeconds);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("timestamp", timestamp);
        response.put("userId", userId);
        response.put("action", request.action().toUpperCase());
        response.put("riskScore", request.riskScore());
        response.put("confidence", request.confidence());
        response.put("threatLevel", calculateThreatLevel(request.riskScore()));
        response.put("isAnomaly", request.riskScore() > 0.7);
        response.put("ttlSeconds", ttlSeconds);
        response.put("message", String.format("Action이 '%s'으로 설정되었습니다.", request.action().toUpperCase()));

        return ResponseEntity.ok(response);
    }

    /**
     * 분석 결과 초기화 (PENDING_ANALYSIS 상태로 복귀)
     *
     * Redis에서 HCAD 분석 결과와 위협 점수를 삭제한다.
     * 이후 SpEL 표현식 평가 시 PENDING_ANALYSIS로 처리된다.
     *
     * @param user 인증된 사용자
     * @return 초기화 결과
     */
    @DeleteMapping("/reset")
    public ResponseEntity<Map<String, Object>> resetAction(
            @AuthenticationPrincipal UserDetails user) {

        String userId = extractUserId(user);
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);

        log.info("[Action 초기화] 시작 - userId: {}", userId);

        // HCAD 분석 결과 삭제
        String hcadKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
        Boolean hcadDeleted = redisTemplate.delete(hcadKey);

        // threat_score 삭제 (Dual-Delete)
        String threatKey = ZeroTrustRedisKeys.threatScore(userId);
        Boolean threatDeleted = redisTemplate.delete(threatKey);

        log.info("[Action 초기화] 완료 - userId: {}, hcadDeleted: {}, threatDeleted: {}",
            userId, hcadDeleted, threatDeleted);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("timestamp", timestamp);
        response.put("userId", userId);
        response.put("hcadAnalysisDeleted", Boolean.TRUE.equals(hcadDeleted));
        response.put("threatScoreDeleted", Boolean.TRUE.equals(threatDeleted));
        response.put("currentAction", "PENDING_ANALYSIS");
        response.put("message", "분석 결과가 초기화되었습니다. 현재 상태는 PENDING_ANALYSIS입니다.");

        return ResponseEntity.ok(response);
    }

    /**
     * 사용자 ID 추출
     */
    private String extractUserId(UserDetails user) {
        if (user != null) {
            return user.getUsername();
        }

        // fallback: SecurityContext에서 직접 조회
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName() != null) {
            return auth.getName();
        }

        throw new IllegalStateException("인증된 사용자 정보를 찾을 수 없습니다.");
    }

    /**
     * Action 설정 요청 유효성 검사
     */
    private Map<String, Object> validateActionRequest(ActionSetRequest request) {
        if (request == null) {
            return createValidationError("요청 본문이 비어있습니다.");
        }

        if (request.action() == null || request.action().isBlank()) {
            return createValidationError("action은 필수입니다.");
        }

        String upperAction = request.action().toUpperCase();
        boolean validAction = false;
        for (String valid : VALID_ACTIONS) {
            if (valid.equals(upperAction)) {
                validAction = true;
                break;
            }
        }

        if (!validAction) {
            return createValidationError(
                String.format("유효하지 않은 action입니다. 허용 값: %s", String.join(", ", VALID_ACTIONS)));
        }

        if (request.riskScore() < 0.0 || request.riskScore() > 1.0) {
            return createValidationError("riskScore는 0.0 ~ 1.0 범위여야 합니다.");
        }

        if (request.confidence() < 0.0 || request.confidence() > 1.0) {
            return createValidationError("confidence는 0.0 ~ 1.0 범위여야 합니다.");
        }

        return null; // 유효함
    }

    /**
     * 유효성 검사 오류 응답 생성
     */
    private Map<String, Object> createValidationError(String message) {
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("success", false);
        error.put("error", "ValidationError");
        error.put("message", message);
        return error;
    }

    /**
     * 위협 레벨 계산
     *
     * riskScore 기반으로 위협 레벨을 결정한다.
     * - CRITICAL: 0.9 이상
     * - HIGH: 0.7 이상
     * - MEDIUM: 0.4 이상
     * - LOW: 0.2 이상
     * - INFO: 0.2 미만
     */
    private String calculateThreatLevel(double riskScore) {
        if (riskScore >= 0.9) return "CRITICAL";
        if (riskScore >= 0.7) return "HIGH";
        if (riskScore >= 0.4) return "MEDIUM";
        if (riskScore >= 0.2) return "LOW";
        return "INFO";
    }

    /**
     * Action별 TTL 계산 (초 단위)
     *
     * Action 유형에 따라 Redis 키의 TTL을 결정한다.
     * - BLOCK: 24시간 (영구적 차단에 가까움)
     * - INVESTIGATE, ESCALATE: 5분 (빠른 재평가 필요)
     * - CHALLENGE: 10분 (MFA 완료 대기)
     * - MONITOR: 10분 (관찰 모드)
     * - ALLOW: 1시간 (정상 상태)
     */
    private long calculateTtlByAction(String action) {
        String upperAction = action.toUpperCase();
        return switch (upperAction) {
            case "BLOCK" -> 86400L;      // 24시간
            case "INVESTIGATE" -> 300L;   // 5분
            case "ESCALATE" -> 300L;      // 5분
            case "CHALLENGE" -> 600L;     // 10분
            case "MONITOR" -> 600L;       // 10분
            case "ALLOW" -> 3600L;        // 1시간
            default -> 600L;              // 기본 10분
        };
    }

    /**
     * 위협 유형 결정
     */
    private String determineThreatType(String action, double riskScore) {
        String upperAction = action.toUpperCase();
        if ("BLOCK".equals(upperAction)) {
            if (riskScore >= 0.9) return "CRITICAL_THREAT_DETECTED";
            if (riskScore >= 0.7) return "HIGH_RISK_BEHAVIOR";
            return "POLICY_VIOLATION";
        }
        if ("CHALLENGE".equals(upperAction)) {
            return "AUTHENTICATION_REQUIRED";
        }
        if ("INVESTIGATE".equals(upperAction) || "ESCALATE".equals(upperAction)) {
            return "SUSPICIOUS_ACTIVITY";
        }
        if ("MONITOR".equals(upperAction)) {
            return "BEHAVIORAL_ANOMALY";
        }
        return "NORMAL_ACTIVITY";
    }

    /**
     * 위협 증거 생성
     */
    private String generateThreatEvidence(String action, double riskScore) {
        String upperAction = action.toUpperCase();
        return String.format(
            "[TEST] Action: %s, RiskScore: %.2f - 테스트 목적으로 설정된 LLM 분석 결과",
            upperAction, riskScore);
    }

    /**
     * Action 설정 요청 DTO
     *
     * @param action LLM이 결정한 Action (ALLOW, BLOCK, CHALLENGE, INVESTIGATE, ESCALATE, MONITOR)
     * @param riskScore 위험 점수 (0.0 ~ 1.0)
     * @param confidence 분석 신뢰도 (0.0 ~ 1.0)
     */
    public record ActionSetRequest(
        String action,
        double riskScore,
        double confidence
    ) {}
}
