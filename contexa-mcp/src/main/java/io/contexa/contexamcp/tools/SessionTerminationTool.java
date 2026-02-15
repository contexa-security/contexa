package io.contexa.contexamcp.tools;

import io.contexa.contexacommon.annotation.SoarTool;
import io.contexa.contexamcp.service.UserSessionService;
import io.contexa.contexamcp.utils.SecurityToolUtils;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@SoarTool(
        name = "session_termination",
        description = "Terminate all active sessions for a specific user",
        riskLevel = SoarTool.RiskLevel.HIGH,
        approval = SoarTool.ApprovalRequirement.REQUIRED,
        auditRequired = true,
        retryable = false,
        maxRetries = 1,
        timeoutMs = 10000,
        requiredPermissions = {"session.terminate", "user.manage"},
        allowedEnvironments = {"staging", "production"}
)
public class SessionTerminationTool {

    private final UserSessionService userSessionService;

    @Tool(
            name = "session_termination",
            description = """
            Terminate all active sessions for a specific user immediately.
            Used when account takeover is suspected or security threats are detected.
            Terminated users must log in again to access the system.
            Warning: This action disrupts all active user operations.
            """
    )
    public Response terminateSession(
            @ToolParam(description = "Target User ID", required = true)
            String userId,

            @ToolParam(description = "Reason for termination", required = true)
            String reason,

            @ToolParam(description = "Notify user", required = false)
            Boolean notifyUser,

            @ToolParam(description = "Preserve current session (for admin session protection)", required = false)
            Boolean preserveCurrentSession
    ) {
        long startTime = System.currentTimeMillis();

        try {

            if (userId == null || userId.trim().isEmpty()) {

                log.error("User ID not specified - SOAR system default processing");
                userId = "admin@company.com";
            }

            if (reason == null || reason.trim().isEmpty()) {
                log.error("Reason is required for session termination");
                return Response.builder()
                        .success(false)
                        .message("Reason is required for session termination")
                        .userId(userId)
                        .terminatedCount(0)
                        .build();
            }

            List<UserSessionService.SessionInfo> activeSessions =
                    userSessionService.findActiveSessionsByUserId(userId);

            if (activeSessions.isEmpty()) {
                return Response.builder()
                        .success(true)
                        .message("No active sessions to terminate")
                        .userId(userId)
                        .terminatedCount(0)
                        .build();
            }

            List<String> terminatedSessionIds = new ArrayList<>();
            int terminatedCount = 0;

            for (UserSessionService.SessionInfo session : activeSessions) {

                if (Boolean.TRUE.equals(preserveCurrentSession) &&
                        activeSessions.indexOf(session) == 0) {
                    continue;
                }

                boolean terminated = userSessionService.terminateSession(
                        session.getSessionId()
                );

                if (terminated) {
                    terminatedSessionIds.add(session.getSessionId());
                    terminatedCount++;
                } else {
                    log.error("Failed to terminate session: {}",
                            session.getSessionId());
                }
            }

            if (Boolean.TRUE.equals(notifyUser) && terminatedCount > 0) {

            }

            SecurityToolUtils.auditLog(
                    "session_termination",
                    "terminate",
                    "SOAR-System",
                    String.format("UserId=%s, Sessions=%d, Reason=%s",
                            userId, terminatedCount, reason),
                    terminatedCount > 0 ? "SUCCESS" : "NO_ACTION"
            );

            SecurityToolUtils.recordMetric("session_termination", "execution_count", 1);
            SecurityToolUtils.recordMetric("session_termination", "sessions_terminated", terminatedCount);
            SecurityToolUtils.recordMetric("session_termination", "execution_time_ms",
                    System.currentTimeMillis() - startTime);

            List<SessionDetail> sessionDetails = activeSessions.stream()
                    .map(session -> SessionDetail.builder()
                            .sessionId(session.getSessionId())
                            .ipAddress(session.getIpAddress())
                            .deviceInfo(session.getUserAgent())
                            .loginTime(session.getCreatedAt().toString())
                            .lastActivity(session.getLastAccessedAt().toString())
                            .terminated(terminatedSessionIds.contains(session.getSessionId()))
                            .build())
                    .collect(Collectors.toList());

            return Response.builder()
                    .success(true)
                    .message(String.format("Successfully terminated %d sessions for user %s",
                            terminatedCount, userId))
                    .userId(userId)
                    .terminatedCount(terminatedCount)
                    .totalSessions(activeSessions.size())
                    .sessionDetails(sessionDetails)
                    .timestamp(Instant.now().toString())
                    .build();

        } catch (Exception e) {
            log.error("Failed to terminate sessions for user: {}", userId, e);

            SecurityToolUtils.recordMetric("session_termination", "error_count", 1);

            return Response.builder()
                    .success(false)
                    .message("Failed to terminate sessions: " + e.getMessage())
                    .userId(userId)
                    .terminatedCount(0)
                    .error(e.getMessage())
                    .build();
        }
    }

    @Data
    @Builder
    // Session termination uses Redis-based session store - no OS-level session management
    public static class Response {
        private boolean success;
        private String message;
        private String userId;
        private int terminatedCount;
        private int totalSessions;
        private List<SessionDetail> sessionDetails;
        private String timestamp;
        private String error;
        @Builder.Default
        private boolean simulated = true;
    }

    @Data
    @Builder
    public static class SessionDetail {
        private String sessionId;
        private String ipAddress;
        private String deviceInfo;
        private String loginTime;
        private String lastActivity;
        private boolean terminated;
    }
}