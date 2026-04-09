package io.contexa.springbootstartercontexa.web;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.springbootstartercontexa.service.SecurityTestAnalysisSnapshotService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping({"/api/test-action", "/admin/api/test-action"})
@RequiredArgsConstructor
public class TestActionController {

    private static final DateTimeFormatter TIMESTAMP_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    private final ZeroTrustActionRepository actionRepository;
    private final SecurityTestAnalysisSnapshotService analysisSnapshotService;

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getActionStatus(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(required = false) String requestId) {

        String userId = extractUserId(user);
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);

        SecurityTestAnalysisSnapshotService.AnalysisSnapshot snapshot =
                analysisSnapshotService.resolveSnapshot(userId, requestId);

        Map<String, Object> response = new LinkedHashMap<>(snapshot.toMap(userId));
        response.put("timestamp", timestamp);
        if (response.get("action") == null) {
            response.put("action", ZeroTrustAction.PENDING_ANALYSIS.name());
        }
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/reset")
    public ResponseEntity<Map<String, Object>> resetAction(
            @AuthenticationPrincipal UserDetails user) {

        String userId = extractUserId(user);
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);

        actionRepository.removeAllUserData(userId);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("timestamp", timestamp);
        response.put("userId", userId);
        response.put("currentAction", ZeroTrustAction.PENDING_ANALYSIS.name());

        return ResponseEntity.ok(response);
    }

    private String extractUserId(UserDetails user) {
        if (user != null) {
            return user.getUsername();
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName() != null) {
            return auth.getName();
        }

        throw new IllegalStateException("Cannot find authenticated user information.");
    }
}
