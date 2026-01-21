package io.contexa.springbootstartercontexa.web;

import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 관리자 개입 REST API 컨트롤러 (AI Native v3.5.0)
 *
 * LLM이 BLOCK 판정을 내린 요청에 대해 관리자가 검토하고
 * 승인/거부를 결정할 수 있는 API를 제공합니다.
 *
 * AI Native 원칙:
 * - 관리자 승인 시 Redis analysis 키 업데이트
 * - 명시적 baselineUpdateAllowed 설정 시에만 Baseline 학습
 * - 모든 개입은 감사 로그로 기록
 *
 * API 엔드포인트:
 * - GET  /api/admin/override/pending       : 대기 중인 요청 목록 조회
 * - GET  /api/admin/override/pending/{id}  : 대기 중인 요청 상세 조회
 * - POST /api/admin/override/approve       : 요청 승인 (ALLOW 전환)
 * - POST /api/admin/override/reject        : 요청 거부 (BLOCK 유지)
 * - GET  /api/admin/override/history       : 관리자 개입 이력 조회
 *
 * @author contexa
 * @since 3.5.0
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/override")
@RequiredArgsConstructor
@ConditionalOnBean(AdminOverrideService.class)
public class AdminOverrideController {

    private final AdminOverrideService adminOverrideService;
    private final StringRedisTemplate redisTemplate;

    private static final DateTimeFormatter TIMESTAMP_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    /**
     * 대기 중인 요청 상세 조회
     *
     * @param requestId 요청 ID
     * @return 대기 중인 요청 정보
     */
    @GetMapping("/pending/{requestId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getPendingRequest(@PathVariable String requestId) {
        log.info("[AdminOverride] 대기 요청 조회: requestId={}", requestId);

        Optional<Map<Object, Object>> pendingOpt = adminOverrideService.getPendingReview(requestId);

        if (pendingOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        Map<Object, Object> pending = pendingOpt.get();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("timestamp", LocalDateTime.now().format(TIMESTAMP_FORMATTER));
        response.put("requestId", requestId);
        response.put("status", "PENDING");

        // pending 데이터 복사
        for (Map.Entry<Object, Object> entry : pending.entrySet()) {
            response.put(entry.getKey().toString(), entry.getValue());
        }

        return ResponseEntity.ok(response);
    }

    /**
     * 현재 사용자의 대기 중인 BLOCK 요청 조회
     *
     * 테스트 페이지에서 현재 사용자의 BLOCK 요청을 조회합니다.
     *
     * @return 현재 사용자의 대기 중인 요청 정보
     */
    @GetMapping("/pending/current")
    public ResponseEntity<Map<String, Object>> getCurrentUserPendingRequest() {
        String userId = extractCurrentUserId();
        log.info("[AdminOverride] 현재 사용자 대기 요청 조회: userId={}", userId);

        // Redis에서 현재 사용자의 분석 결과 조회
        String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
        Map<Object, Object> analysisData = redisTemplate.opsForHash().entries(analysisKey);

        if (analysisData.isEmpty()) {
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("timestamp", LocalDateTime.now().format(TIMESTAMP_FORMATTER));
            response.put("userId", userId);
            response.put("hasPending", false);
            response.put("message", "대기 중인 요청이 없습니다.");
            return ResponseEntity.ok(response);
        }

        String action = (String) analysisData.getOrDefault("action", "PENDING_ANALYSIS");
        boolean isBlocked = "BLOCK".equalsIgnoreCase(action) ||
                           "CHALLENGE".equalsIgnoreCase(action) ||
                           "ESCALATE".equalsIgnoreCase(action);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("timestamp", LocalDateTime.now().format(TIMESTAMP_FORMATTER));
        response.put("userId", userId);
        response.put("hasPending", isBlocked);
        response.put("action", action);
        response.put("riskScore", parseDouble((String) analysisData.getOrDefault("riskScore", "0.0")));
        response.put("confidence", parseDouble((String) analysisData.getOrDefault("confidence", "0.0")));
        response.put("threatLevel", analysisData.getOrDefault("threatLevel", "UNKNOWN"));
        response.put("reasoning", analysisData.getOrDefault("reasoning", ""));

        if (isBlocked) {
            // requestId 생성 (userId + timestamp 조합)
            String requestId = generateRequestId(userId);
            response.put("requestId", requestId);
            response.put("message", "관리자 승인이 필요한 요청입니다.");
        } else {
            response.put("message", "대기 중인 요청이 없습니다.");
        }

        return ResponseEntity.ok(response);
    }

    /**
     * 요청 승인 (ALLOW 전환)
     *
     * 관리자가 BLOCK 판정된 요청을 검토 후 ALLOW로 전환합니다.
     *
     * @param request 승인 요청 데이터
     * @return 승인 결과
     */
    @PostMapping("/approve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> approveRequest(@RequestBody ApproveRequest request) {
        String adminId = extractCurrentUserId();
        log.info("[AdminOverride] 요청 승인: requestId={}, userId={}, adminId={}, baselineUpdateAllowed={}",
            request.getRequestId(), request.getUserId(), adminId, request.isBaselineUpdateAllowed());

        // 필수값 검증
        if (request.getRequestId() == null || request.getRequestId().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "requestId는 필수입니다."
            ));
        }

        if (request.getReason() == null || request.getReason().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "승인 사유는 필수입니다."
            ));
        }

        try {
            // 저장된 SecurityEvent 조회 (Baseline 학습용)
            SecurityEvent originalEvent = adminOverrideService.getSecurityEvent(request.getRequestId())
                .orElse(null);

            // 승인 처리
            AdminOverride override = adminOverrideService.approve(
                request.getRequestId(),
                request.getUserId(),
                adminId,
                request.getOriginalAction(),
                request.getOriginalRiskScore(),
                request.getOriginalConfidence(),
                "ALLOW",
                request.getReason(),
                request.isBaselineUpdateAllowed(),
                originalEvent
            );

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("timestamp", LocalDateTime.now().format(TIMESTAMP_FORMATTER));
            response.put("overrideId", override.getOverrideId());
            response.put("requestId", override.getRequestId());
            response.put("userId", override.getUserId());
            response.put("adminId", override.getAdminId());
            response.put("originalAction", override.getOriginalAction());
            response.put("overriddenAction", override.getOverriddenAction());
            response.put("baselineUpdateAllowed", override.isBaselineUpdateAllowed());
            response.put("baselineLearned", override.canUpdateBaseline() && originalEvent != null);
            response.put("message", "요청이 승인되었습니다." +
                (override.canUpdateBaseline() ? " Baseline 학습이 수행되었습니다." : ""));

            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", e.getMessage()
            ));
        } catch (Exception e) {
            log.error("[AdminOverride] 승인 처리 실패: requestId={}", request.getRequestId(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "승인 처리 중 오류가 발생했습니다: " + e.getMessage()
            ));
        }
    }

    /**
     * 요청 거부 (BLOCK 유지)
     *
     * 관리자가 BLOCK 판정이 정당하다고 판단하여 거부합니다.
     *
     * @param request 거부 요청 데이터
     * @return 거부 결과
     */
    @PostMapping("/reject")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> rejectRequest(@RequestBody RejectRequest request) {
        String adminId = extractCurrentUserId();
        log.info("[AdminOverride] 요청 거부: requestId={}, userId={}, adminId={}",
            request.getRequestId(), request.getUserId(), adminId);

        // 필수값 검증
        if (request.getRequestId() == null || request.getRequestId().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "requestId는 필수입니다."
            ));
        }

        if (request.getReason() == null || request.getReason().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "거부 사유는 필수입니다."
            ));
        }

        try {
            AdminOverride override = adminOverrideService.reject(
                request.getRequestId(),
                request.getUserId(),
                adminId,
                request.getOriginalAction(),
                request.getOriginalRiskScore(),
                request.getOriginalConfidence(),
                request.getReason()
            );

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("timestamp", LocalDateTime.now().format(TIMESTAMP_FORMATTER));
            response.put("overrideId", override.getOverrideId());
            response.put("requestId", override.getRequestId());
            response.put("userId", override.getUserId());
            response.put("adminId", override.getAdminId());
            response.put("originalAction", override.getOriginalAction());
            response.put("overriddenAction", override.getOverriddenAction());
            response.put("message", "요청이 거부되었습니다. BLOCK 상태가 유지됩니다.");

            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", e.getMessage()
            ));
        } catch (Exception e) {
            log.error("[AdminOverride] 거부 처리 실패: requestId={}", request.getRequestId(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "거부 처리 중 오류가 발생했습니다: " + e.getMessage()
            ));
        }
    }

    /**
     * 관리자 개입 이력 조회
     *
     * 특정 사용자에 대한 관리자 개입 이력을 조회합니다.
     *
     * @param userId 사용자 ID
     * @return 관리자 개입 이력 목록
     */
    @GetMapping("/history")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getOverrideHistory(
            @RequestParam(required = false) String userId) {

        String targetUserId = userId != null ? userId : extractCurrentUserId();
        log.info("[AdminOverride] 개입 이력 조회: userId={}", targetUserId);

        Optional<AdminOverride> overrideOpt = Optional.empty();
        // findByRequestId를 사용하여 조회 (userId 기반 조회는 Repository에서 구현 필요)

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("timestamp", LocalDateTime.now().format(TIMESTAMP_FORMATTER));
        response.put("userId", targetUserId);
        response.put("history", new ArrayList<>()); // 이력 목록 (구현 필요)
        response.put("message", "이력 조회 기능은 향후 업데이트에서 제공될 예정입니다.");

        return ResponseEntity.ok(response);
    }

    /**
     * 현재 사용자 ID 추출
     */
    private String extractCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName() != null) {
            return auth.getName();
        }
        throw new IllegalStateException("인증된 사용자 정보를 찾을 수 없습니다.");
    }

    /**
     * 요청 ID 생성
     */
    private String generateRequestId(String userId) {
        return userId + "-" + System.currentTimeMillis();
    }

    /**
     * 문자열을 double로 파싱
     */
    private double parseDouble(String value) {
        if (value == null || value.isEmpty()) {
            return 0.0;
        }
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException e) {
            return 0.0;
        }
    }

    /**
     * 승인 요청 DTO
     */
    public static class ApproveRequest {
        private String requestId;
        private String userId;
        private String originalAction;
        private double originalRiskScore;
        private double originalConfidence;
        private String reason;
        private boolean baselineUpdateAllowed;

        public String getRequestId() { return requestId; }
        public void setRequestId(String requestId) { this.requestId = requestId; }
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public String getOriginalAction() { return originalAction; }
        public void setOriginalAction(String originalAction) { this.originalAction = originalAction; }
        public double getOriginalRiskScore() { return originalRiskScore; }
        public void setOriginalRiskScore(double originalRiskScore) { this.originalRiskScore = originalRiskScore; }
        public double getOriginalConfidence() { return originalConfidence; }
        public void setOriginalConfidence(double originalConfidence) { this.originalConfidence = originalConfidence; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
        public boolean isBaselineUpdateAllowed() { return baselineUpdateAllowed; }
        public void setBaselineUpdateAllowed(boolean baselineUpdateAllowed) { this.baselineUpdateAllowed = baselineUpdateAllowed; }
    }

    /**
     * 거부 요청 DTO
     */
    public static class RejectRequest {
        private String requestId;
        private String userId;
        private String originalAction;
        private double originalRiskScore;
        private double originalConfidence;
        private String reason;

        public String getRequestId() { return requestId; }
        public void setRequestId(String requestId) { this.requestId = requestId; }
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public String getOriginalAction() { return originalAction; }
        public void setOriginalAction(String originalAction) { this.originalAction = originalAction; }
        public double getOriginalRiskScore() { return originalRiskScore; }
        public void setOriginalRiskScore(double originalRiskScore) { this.originalRiskScore = originalRiskScore; }
        public double getOriginalConfidence() { return originalConfidence; }
        public void setOriginalConfidence(double originalConfidence) { this.originalConfidence = originalConfidence; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
    }
}
