package io.contexa.contexaiam.aiam.web;

import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/aiam/zero-trust")
@RequiredArgsConstructor
public class ZeroTrustUnblockController {

    private final BlockedUserService blockedUserService;

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

        String reason = (request != null && request.getReason() != null)
                ? request.getReason()
                : "User requested unblock";

        try {
            blockedUserService.requestUnblock(userId, reason);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("message", "Unblock request submitted");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("[ZeroTrustUnblockController] Failed to submit unblock request: userId={}", userId, e);
            return ResponseEntity.internalServerError().body(Map.of(
                    "success", false,
                    "message", "Failed to submit request"));
        }
    }

    public static class UnblockRequest {
        private String reason;

        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
    }
}
