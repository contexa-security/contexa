package io.contexa.springbootstartercontexa.web;

import io.contexa.contexacommon.enums.ZeroTrustAction;
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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * LLM Action 상태 조회 컨트롤러 (실제 분석 결과 조회)
 *
 * 실제 LLM 분석 결과를 Redis에서 조회한다.
 * ColdPathEventProcessor가 Layer1/2/3 분석을 수행하고 Redis에 저장한 결과를 조회한다.
 *
 * 실제 플로우:
 * 1. 클라이언트가 @Protectable 메서드 호출
 * 2. AuthorizationManagerMethodInterceptor가 이벤트 발행 (finally 블록)
 * 3. ColdPathEventProcessor가 Layer1/2/3 LLM 분석 수행 (비동기)
 * 4. 분석 결과가 Redis에 저장 (비동기)
 * 5. 이 컨트롤러에서 저장된 결과 조회
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
//@RestController
//@RequestMapping("/api/test-action")
@RequiredArgsConstructor
public class TestActionController {

    private final StringRedisTemplate redisTemplate;

    private static final DateTimeFormatter TIMESTAMP_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

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

            response.put("action", ZeroTrustAction.PENDING_ANALYSIS.name());
            response.put("riskScore", 0.0);
            response.put("confidence", 0.0);
            response.put("threatLevel", "UNKNOWN");
            response.put("isAnomaly", false);
            response.put("analysisStatus", "NOT_ANALYZED");
            response.put("message", "LLM 분석 결과가 없습니다. @Protectable 메서드 호출 후 분석이 완료되면 결과가 표시됩니다.");

            return ResponseEntity.ok(response);
        }

        String action = (String) fields.getOrDefault("action", ZeroTrustAction.PENDING_ANALYSIS.name());
        String riskScoreStr = (String) fields.getOrDefault("riskScore", "0.0");
        String confidenceStr = (String) fields.getOrDefault("confidence", "0.0");
        String threatLevel = (String) fields.getOrDefault("threatLevel", "UNKNOWN");
        String isAnomalyStr = (String) fields.getOrDefault("isAnomaly", "false");
        String updatedAt = (String) fields.get("updatedAt");
        // AI Native v8.12: LLM 분석 근거 및 MITRE 매핑 추가
        String reasoning = (String) fields.get("reasoning");
        String mitre = (String) fields.get("mitre");

        response.put("action", action);
        response.put("riskScore", Double.parseDouble(riskScoreStr));
        response.put("confidence", Double.parseDouble(confidenceStr));
        response.put("threatLevel", threatLevel);
        response.put("isAnomaly", Boolean.parseBoolean(isAnomalyStr));
        response.put("analysisStatus", "ANALYZED");
        response.put("updatedAt", updatedAt);
        // AI Native v8.12: LLM 분석 근거 및 MITRE 매핑
        if (reasoning != null) {
            response.put("reasoning", reasoning);
        }
        if (mitre != null && !"none".equals(mitre)) {
            response.put("mitre", mitre);
        }

        log.info("[Action 상태 조회] 완료 - userId: {}, action: {}, riskScore: {}",
            userId, action, riskScoreStr);

        return ResponseEntity.ok(response);
    }

    /**
     * 분석 결과 초기화 (PENDING_ANALYSIS 상태로 복귀)
     *
     * Redis에서 HCAD 분석 결과와 위협 점수를 삭제한다.
     * 이후 SpEL 표현식 평가 시 PENDING_ANALYSIS로 처리된다.
     * 테스트 시나리오 시작 전 상태 초기화에 사용한다.
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
        response.put("currentAction", ZeroTrustAction.PENDING_ANALYSIS.name());
        response.put("message", "분석 결과가 초기화되었습니다. 새로운 시나리오 테스트를 시작할 수 있습니다.");

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
}
