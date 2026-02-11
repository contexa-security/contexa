package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/api/admin/override")
@RequiredArgsConstructor
public class AdminOverrideController {

    private final AdminOverrideService adminOverrideService;
    private final StringRedisTemplate redisTemplate;

    private static final DateTimeFormatter TIMESTAMP_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    @GetMapping("/pending/{requestId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getPendingRequest(@PathVariable String requestId) {
        Optional<Map<Object, Object>> pendingOpt = adminOverrideService.getPendingReview(requestId);

        if (pendingOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        Map<Object, Object> pending = pendingOpt.get();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("timestamp", LocalDateTime.now().format(TIMESTAMP_FORMATTER));
        response.put("requestId", requestId);
        response.put("status", "PENDING");

        for (Map.Entry<Object, Object> entry : pending.entrySet()) {
            response.put(entry.getKey().toString(), entry.getValue());
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/pending/current")
    public ResponseEntity<Map<String, Object>> getCurrentUserPendingRequest() {
        String userId = extractCurrentUserId();

        String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
        Map<Object, Object> analysisData = redisTemplate.opsForHash().entries(analysisKey);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("timestamp", LocalDateTime.now().format(TIMESTAMP_FORMATTER));
        response.put("userId", userId);

        if (analysisData.isEmpty()) {
            response.put("hasPending", false);
            response.put("message", "No pending request found.");
            return ResponseEntity.ok(response);
        }

        String action = (String) analysisData.getOrDefault("action", "PENDING_ANALYSIS");
        boolean isBlocked = "BLOCK".equalsIgnoreCase(action) ||
                           "CHALLENGE".equalsIgnoreCase(action) ||
                           "ESCALATE".equalsIgnoreCase(action);

        response.put("hasPending", isBlocked);
        response.put("action", action);
        response.put("riskScore", parseDouble((String) analysisData.getOrDefault("riskScore", "0.0")));
        response.put("confidence", parseDouble((String) analysisData.getOrDefault("confidence", "0.0")));
        response.put("threatLevel", analysisData.getOrDefault("threatLevel", "UNKNOWN"));
        response.put("reasoning", analysisData.getOrDefault("reasoning", ""));

        if (!isBlocked) {
            response.put("message", "No pending request found.");
        }

        return ResponseEntity.ok(response);
    }

    @PostMapping("/approve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> approveRequest(@RequestBody ApproveRequest request) {
        String adminId = extractCurrentUserId();

        if (request.getRequestId() == null || request.getRequestId().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "requestId is required."
            ));
        }

        if (request.getReason() == null || request.getReason().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "Reason is required."
            ));
        }

        try {
            SecurityEvent originalEvent = adminOverrideService.getSecurityEvent(request.getRequestId())
                .orElse(null);

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

            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", e.getMessage()
            ));
        } catch (Exception e) {
            log.error("[AdminOverrideController] Failed to approve request: requestId={}", request.getRequestId(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to approve request: " + e.getMessage()
            ));
        }
    }

    @PostMapping("/reject")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> rejectRequest(@RequestBody RejectRequest request) {
        String adminId = extractCurrentUserId();

        if (request.getRequestId() == null || request.getRequestId().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "requestId is required."
            ));
        }

        if (request.getReason() == null || request.getReason().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "Reason is required."
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

            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", e.getMessage()
            ));
        } catch (Exception e) {
            log.error("[AdminOverrideController] Failed to reject request: requestId={}", request.getRequestId(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to reject request: " + e.getMessage()
            ));
        }
    }

    @GetMapping("/history")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> getOverrideHistory(@RequestParam(required = false) String userId) {
        return ResponseEntity.status(301)
            .header("Location", "/api/admin/blacklist")
            .build();
    }

    private String extractCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName() != null) {
            return auth.getName();
        }
        throw new IllegalStateException("Authenticated user not found");
    }

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
