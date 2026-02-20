package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * REST controller for user-initiated unblock requests.
 */
@Slf4j
@RestController
@RequestMapping("/api/aiam/zero-trust")
@RequiredArgsConstructor
public class ZeroTrustUnblockController {

    private final AdminOverrideService adminOverrideService;
    private final StringRedisTemplate redisTemplate;

    @PostMapping("/unblock-request")
    public ResponseEntity<Map<String, Object>> requestUnblock(
            Principal principal,
            @RequestBody(required = false) UnblockRequest request) {

        String userId = principal != null ? principal.getName() : null;
        if (userId == null) {
            return ResponseEntity.status(401).body(Map.of(
                    "success", false,
                    "message", "Authentication required"));
        }

        String requestId = UUID.randomUUID().toString();
        String reason = (request != null && request.getReason() != null)
                ? request.getReason()
                : "User requested unblock";

        String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
        Map<Object, Object> analysisData = redisTemplate.opsForHash().entries(analysisKey);

        double riskScore = parseDouble(analysisData.get("riskScore"));
        double confidence = parseDouble(analysisData.get("confidence"));
        String reasoning = analysisData.containsKey("reasoning")
                ? analysisData.get("reasoning").toString()
                : reason;

        try {
            adminOverrideService.addToPendingReview(
                    requestId, userId, riskScore, confidence, reasoning);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("message", "Unblock request submitted");
            response.put("requestId", requestId);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("[ZeroTrustUnblockController] Failed to submit unblock request: userId={}", userId, e);
            return ResponseEntity.internalServerError().body(Map.of(
                    "success", false,
                    "message", "Failed to submit request"));
        }
    }

    private double parseDouble(Object value) {
        if (value == null) {
            return 0.0;
        }
        try {
            return Double.parseDouble(value.toString());
        } catch (NumberFormatException e) {
            return 0.0;
        }
    }

    public static class UnblockRequest {
        private String reason;

        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
    }
}
