package io.contexa.contexamcp.tools;

import io.contexa.contexacommon.annotation.SoarTool;
import io.contexa.contexacommon.soar.event.SecurityActionEvent;
import io.contexa.contexamcp.adapter.ExternalFirewallAdapter;
import io.contexa.contexamcp.security.HighRiskToolAuthorizationService;
import io.contexa.contexamcp.service.IpBlockingService;
import io.contexa.contexamcp.utils.SecurityToolUtils;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@SoarTool(
        name = "ip_blocking",
        description = "Block malicious IP addresses in network firewall",
        riskLevel = SoarTool.RiskLevel.HIGH,
        approval = SoarTool.ApprovalRequirement.REQUIRED,
        auditRequired = true,
        retryable = false,
        maxRetries = 1,
        timeoutMs = 10000,
        requiredPermissions = {"network.block", "firewall.manage"},
        allowedEnvironments = {"staging", "production"}
)
public class IpBlockingTool {

    private final IpBlockingService ipBlockingService;
    private final HighRiskToolAuthorizationService authorizationService;
    private final ExternalFirewallAdapter firewallAdapter;
    private final ApplicationEventPublisher eventPublisher;

    @Tool(
            name = "ip_blocking",
            description = """
            Blocks specific IP addresses in the network firewall.
            Can immediately block access from IP addresses where security threats are detected.
            Duration can be specified, or permanent blocking is possible.
            """
    )
    public Response blockIp(
            @ToolParam(description = "IP address to block (IPv4 format)", required = true)
            String ipAddress,

            @ToolParam(description = "Reason for blocking (min 10 chars)", required = true)
            String reason,

            @ToolParam(description = "Duration in minutes (null or 0 for permanent)", required = false)
            Integer durationMinutes,

            @ToolParam(description = "Related security ticket ID", required = false)
            String ticketId) {

        long startTime = System.currentTimeMillis();

        try {
            if (!hasRequiredPermissions()) {
                throw new SecurityException("Insufficient permissions to block IP address");
            }

            if (ipAddress == null || ipAddress.trim().isEmpty()) {
                throw new IllegalArgumentException("IP address is required");
            }

            if (reason == null || reason.trim().length() < 10) {
                throw new IllegalArgumentException("Reason must be at least 10 characters");
            }

            if (!SecurityToolUtils.isValidIpv4Address(ipAddress)) {
                log.error("Invalid IP address format: {}", ipAddress);
                return Response.builder()
                        .success(false)
                        .message("Invalid IP address format: " + ipAddress)
                        .ipAddress(ipAddress)
                        .blocked(false)
                        .build();
            }

            if (SecurityToolUtils.isInternalIpAddress(ipAddress)) {
                log.error("Cannot block internal IP address: {}", ipAddress);
                return Response.builder()
                        .success(false)
                        .message("Cannot block internal IP address")
                        .ipAddress(ipAddress)
                        .blocked(false)
                        .build();
            }

            Duration duration = durationMinutes != null && durationMinutes > 0
                    ? Duration.ofMinutes(durationMinutes)
                    : null;

            // Step 1: Internal Redis blocking
            IpBlockingService.BlockResult blockResult = ipBlockingService.blockIp(
                    ipAddress, reason, duration, "SOAR-System");

            if (!blockResult.isSuccess()) {
                log.error("Internal IP blocking failed: {} - {}", ipAddress, blockResult.getMessage());
                return Response.builder()
                        .success(false)
                        .message(blockResult.getMessage())
                        .ipAddress(ipAddress)
                        .blocked(false)
                        .build();
            }

            // Step 2: External firewall blocking via adapter
            boolean externalEngaged = firewallAdapter.isAvailable();
            String externalRuleId = null;
            if (externalEngaged) {
                ExternalFirewallAdapter.BlockResult fwResult =
                        firewallAdapter.blockIp(ipAddress, reason, durationMinutes);
                if (!fwResult.success()) {
                    log.error("External firewall blocking failed: {} - {}", ipAddress, fwResult.message());
                }
                externalRuleId = fwResult.ruleId();
            }

            // Step 3: Publish security action event
            publishIpBlockEvent(ipAddress, reason, durationMinutes, ticketId);

            SecurityToolUtils.auditLog(
                    "ip_blocking", "block", "SOAR-System",
                    String.format("IP=%s, Reason=%s, Duration=%s, Ticket=%s, FW=%s",
                            ipAddress, reason, durationMinutes, ticketId,
                            firewallAdapter.getVendorName()),
                    "SUCCESS"
            );

            SecurityToolUtils.recordMetric("ip_blocking", "execution_count", 1);
            SecurityToolUtils.recordMetric("ip_blocking", "execution_time_ms",
                    System.currentTimeMillis() - startTime);

            return Response.builder()
                    .success(true)
                    .message(blockResult.getMessage())
                    .ipAddress(ipAddress)
                    .blocked(true)
                    .blockedAt(Instant.now().toString())
                    .expiresAt(blockResult.getBlockedUntil() != null
                            ? blockResult.getBlockedUntil().toString()
                            : "PERMANENT")
                    .ruleId(externalRuleId != null
                            ? externalRuleId
                            : generateRuleId(ipAddress, System.currentTimeMillis()))
                    .externalFirewallEngaged(externalEngaged)
                    .firewallVendor(firewallAdapter.getVendorName())
                    .build();

        } catch (IllegalArgumentException e) {
            log.error("Invalid input for IP blocking: {}", e.getMessage());
            return Response.builder()
                    .success(false)
                    .message("Invalid input: " + e.getMessage())
                    .ipAddress(ipAddress)
                    .blocked(false)
                    .build();
        } catch (Exception e) {
            log.error("Error blocking IP address", e);

            SecurityToolUtils.recordMetric("ip_blocking", "error_count", 1);

            return Response.builder()
                    .success(false)
                    .message("Error blocking IP: " + e.getMessage())
                    .ipAddress(ipAddress)
                    .blocked(false)
                    .build();
        }
    }

    private void publishIpBlockEvent(String ipAddress, String reason,
                                      Integer durationMinutes, String ticketId) {
        try {
            SecurityActionEvent event = SecurityActionEvent.builder()
                    .eventId(UUID.randomUUID().toString())
                    .actionType(SecurityActionEvent.ActionType.IP_BLOCK)
                    .sourceIp(ipAddress)
                    .reason(reason)
                    .triggeredBy("SOAR-System")
                    .metadata(Map.of(
                            "durationMinutes", durationMinutes != null ? durationMinutes : 0,
                            "ticketId", ticketId != null ? ticketId : ""
                    ))
                    .build();
            eventPublisher.publishEvent(event);
        } catch (Exception e) {
            log.error("Failed to publish IP block event for: {}", ipAddress, e);
        }
    }

    private boolean hasRequiredPermissions() {
        return authorizationService.isAuthorized("ip_blocking");
    }

    private String generateRuleId(String ipAddress, long timestamp) {
        return String.format("BLOCK_%s_%d",
                ipAddress.replace(".", "_"),
                timestamp);
    }

    @Data
    @Builder
    // IP blocking uses Redis (internal) + external firewall adapter
    public static class Response {
        private boolean success;
        private String message;
        private String ipAddress;
        private boolean blocked;
        private String blockedAt;
        private String expiresAt;
        private String ruleId;
        private boolean externalFirewallEngaged;
        private String firewallVendor;
    }
}
