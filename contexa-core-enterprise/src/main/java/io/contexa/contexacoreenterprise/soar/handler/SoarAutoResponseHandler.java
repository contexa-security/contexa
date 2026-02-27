package io.contexa.contexacoreenterprise.soar.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.soar.event.SecurityActionEvent;
import io.contexa.contexacore.autonomous.service.IForceLogoutService;
import io.contexa.contexacoreenterprise.mcp.tool.resolution.ChainedToolResolver;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;

import java.util.HashMap;
import java.util.Map;

/**
 * Handles SOAR_AUTO_RESPONSE events in the main application JVM.
 * Triggered by BlockedUserTimeoutScheduler (24h timeout) or MFA failure.
 * Calls MCP tools via ChainedToolResolver (HTTP SSE to MCP server)
 * and performs force-logout via IForceLogoutService (main app directly).
 */
@Slf4j
@RequiredArgsConstructor
public class SoarAutoResponseHandler {

    private static final String IP_BLOCKING_TOOL = "ip_blocking";

    private final ChainedToolResolver chainedToolResolver;
    private final ObjectMapper objectMapper;

    @Setter
    @Autowired(required = false)
    private IForceLogoutService forceLogoutService;

    @EventListener
    public void handleAutoResponse(SecurityActionEvent event) {
        if (event.getActionType() != SecurityActionEvent.ActionType.SOAR_AUTO_RESPONSE) {
            return;
        }

        String userId = event.getUserId();
        String sourceIp = event.getSourceIp();
        String reason = event.getReason();

        log.error("[SoarAutoResponse] Processing auto-response: userId={}, sourceIp={}, triggeredBy={}",
                userId, sourceIp, event.getTriggeredBy());

        executeIpBlocking(sourceIp, reason);
        executeForceLogout(userId, reason);
    }

    private void executeIpBlocking(String sourceIp, String reason) {
        if (sourceIp == null || sourceIp.isBlank()) {
            log.error("[SoarAutoResponse] Skipping IP blocking - no source IP available");
            return;
        }

        try {
            ToolCallback ipBlockingTool = chainedToolResolver.resolve(IP_BLOCKING_TOOL);
            if (ipBlockingTool == null) {
                log.error("[SoarAutoResponse] ip_blocking tool not found via ChainedToolResolver");
                return;
            }

            Map<String, Object> args = new HashMap<>();
            args.put("ipAddress", sourceIp);
            args.put("reason", reason);
            args.put("durationMinutes", 1440);

            String jsonArgs = objectMapper.writeValueAsString(args);
            String result = ipBlockingTool.call(jsonArgs);

            log.error("[SoarAutoResponse] IP blocking executed: sourceIp={}, result={}", sourceIp, result);
        } catch (Exception e) {
            log.error("[SoarAutoResponse] Failed to execute IP blocking: sourceIp={}", sourceIp, e);
        }
    }

    private void executeForceLogout(String userId, String reason) {
        if (userId == null || userId.isBlank()) {
            log.error("[SoarAutoResponse] Skipping force-logout - no userId available");
            return;
        }

        if (forceLogoutService == null) {
            log.error("[SoarAutoResponse] ForceLogoutService not available, skipping session/token invalidation");
            return;
        }

        try {
            forceLogoutService.forceLogoutByUserId(userId, reason);
            log.error("[SoarAutoResponse] Force-logout executed: userId={}", userId);
        } catch (Exception e) {
            log.error("[SoarAutoResponse] Failed to execute force-logout: userId={}", userId, e);
        }
    }
}
