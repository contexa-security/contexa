package io.contexa.contexamcp.listener;

import io.contexa.contexacommon.soar.event.SecurityActionEvent;
import io.contexa.contexamcp.tools.IpBlockingTool;
import io.contexa.contexamcp.tools.SessionTerminationTool;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;

/**
 * Listens for SOAR_AUTO_RESPONSE events and executes security tools automatically.
 * Triggered by BlockedUserTimeoutScheduler when blocked users do not request unblock.
 */
@Slf4j
@RequiredArgsConstructor
public class SoarAutoResponseListener {

    private final IpBlockingTool ipBlockingTool;
    private final SessionTerminationTool sessionTerminationTool;

    @EventListener
    public void handleAutoResponse(SecurityActionEvent event) {
        if (event.getActionType() != SecurityActionEvent.ActionType.SOAR_AUTO_RESPONSE) {
            return;
        }

        log.error("SOAR auto-response triggered. userId={}, sourceIp={}",
                event.getUserId(), event.getSourceIp());

        if (event.getSourceIp() != null && !event.getSourceIp().isEmpty()) {
            try {
                ipBlockingTool.blockIp(
                        event.getSourceIp(),
                        "SOAR auto-response: " + event.getReason(),
                        null,
                        event.getEventId());
            } catch (Exception e) {
                log.error("Auto-response IP blocking failed. ip={}", event.getSourceIp(), e);
            }
        }

        if (event.getUserId() != null && !event.getUserId().isEmpty()) {
            try {
                sessionTerminationTool.terminateSession(
                        event.getUserId(),
                        "SOAR auto-response: " + event.getReason(),
                        false,
                        false);
            } catch (Exception e) {
                log.error("Auto-response session termination failed. userId={}", event.getUserId(), e);
            }
        }
    }
}
