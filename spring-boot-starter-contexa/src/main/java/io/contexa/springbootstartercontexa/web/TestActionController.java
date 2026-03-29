package io.contexa.springbootstartercontexa.web;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository.ZeroTrustAnalysisData;
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
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * LLM Action status query controller (actual analysis result retrieval).
 *
 * Retrieves LLM analysis results via ZeroTrustActionRepository.
 * Works in both standalone (InMemory) and distributed (Redis) modes.
 */
@Slf4j
@RestController
@RequestMapping({"/api/test-action", "/admin/api/test-action"})
@RequiredArgsConstructor
public class TestActionController {

    private final ZeroTrustActionRepository actionRepository;

    private static final DateTimeFormatter TIMESTAMP_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    /**
     * Query current user's action status.
     *
     * @param user authenticated user
     * @return current action status
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getActionStatus(
            @AuthenticationPrincipal UserDetails user) {

        String userId = extractUserId(user);
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);

        ZeroTrustAnalysisData data = actionRepository.getAnalysisData(userId);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("timestamp", timestamp);
        response.put("userId", userId);

        if (data.action() == null
                || ZeroTrustAction.PENDING_ANALYSIS.name().equals(data.action())) {

            response.put("action", ZeroTrustAction.PENDING_ANALYSIS.name());
            response.put("riskScore", 0.0);
            response.put("confidence", 0.0);
            response.put("analysisStatus", "NOT_ANALYZED");

            return ResponseEntity.ok(response);
        }

        response.put("action", data.action());
        response.put("riskScore", data.riskScore() != null ? data.riskScore() : 0.0);
        response.put("confidence", data.confidence() != null ? data.confidence() : 0.0);
        response.put("analysisStatus", "ANALYZED");
        response.put("updatedAt", data.updatedAt());
        response.put("reasoning", data.reasoning());
        response.put("reasoningSummary", data.reasoningSummary());
        response.put("requestId", data.requestId());
        response.put("contextBindingHash", data.contextBindingHash());
        response.put("llmProposedAction", data.llmProposedAction());
        response.put("analysisDepth", data.analysisDepth());

        if (data.threatEvidence() != null) {
            response.put("threatEvidence", data.threatEvidence());
        }

        return ResponseEntity.ok(response);
    }

    /**
     * Reset analysis results (return to PENDING_ANALYSIS).
     *
     * @param user authenticated user
     * @return reset result
     */
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
