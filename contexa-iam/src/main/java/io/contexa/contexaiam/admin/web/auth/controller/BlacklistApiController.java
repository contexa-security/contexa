package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/admin/blacklist")
@RequiredArgsConstructor
public class BlacklistApiController {

    private final BlockedUserService blockedUserService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<BlockedUser>> listBlockedUsers(
            @RequestParam(value = "status", required = false) String status) {
        List<BlockedUser> result;
        if ("BLOCKED".equalsIgnoreCase(status)) {
            result = blockedUserService.getBlockedUsers();
        } else {
            result = blockedUserService.getAllBlockHistory();
        }
        return ResponseEntity.ok(result);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<BlockedUser> getBlockDetail(@PathVariable Long id) {
        return blockedUserService.getBlockDetail(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/{id}/resolve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> resolveBlock(
            @PathVariable Long id,
            @RequestBody ResolveRequest request) {
        if (request.resolvedAction == null || request.resolvedAction.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false, "error", "resolvedAction is required"));
        }
        if (request.reason == null || request.reason.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false, "error", "reason is required"));
        }

        try {
            String adminId = extractCurrentUserId();
            blockedUserService.resolveBlockById(id, adminId, request.resolvedAction,
                    request.reason, request.baselineUpdateAllowed);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("id", id);
            response.put("resolvedAction", request.resolvedAction);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("[BlacklistApi] Failed to resolve block: id={}", id, e);
            return ResponseEntity.internalServerError().body(Map.of(
                    "success", false, "error", e.getMessage()));
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> deleteBlockRecord(@PathVariable Long id) {
        try {
            blockedUserService.deleteBlockRecord(id);
            return ResponseEntity.ok(Map.of("success", true, "id", id));
        } catch (Exception e) {
            log.error("[BlacklistApi] Failed to delete block record: id={}", id, e);
            return ResponseEntity.internalServerError().body(Map.of(
                    "success", false, "error", e.getMessage()));
        }
    }

    private String extractCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName() != null) {
            return auth.getName();
        }
        throw new IllegalStateException("Authenticated user not found");
    }

    public static class ResolveRequest {
        public String resolvedAction;
        public String reason;
        public boolean baselineUpdateAllowed;

        public String getResolvedAction() { return resolvedAction; }
        public void setResolvedAction(String resolvedAction) { this.resolvedAction = resolvedAction; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
        public boolean isBaselineUpdateAllowed() { return baselineUpdateAllowed; }
        public void setBaselineUpdateAllowed(boolean baselineUpdateAllowed) { this.baselineUpdateAllowed = baselineUpdateAllowed; }
    }
}
