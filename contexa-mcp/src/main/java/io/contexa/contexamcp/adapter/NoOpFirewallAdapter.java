package io.contexa.contexamcp.adapter;

import lombok.extern.slf4j.Slf4j;

/**
 * Default no-op firewall adapter.
 * Used when no external firewall integration is configured.
 * IP blocking falls back to Redis-only internal blocking.
 */
@Slf4j
public class NoOpFirewallAdapter implements ExternalFirewallAdapter {

    @Override
    public BlockResult blockIp(String ipAddress, String reason, Integer durationMinutes) {
        log.error("No external firewall configured. IP block recorded internally only. ip={}", ipAddress);
        return new BlockResult(true, "No external firewall - internal Redis block only", null);
    }

    @Override
    public BlockResult unblockIp(String ipAddress, String reason) {
        log.error("No external firewall configured. IP unblock recorded internally only. ip={}", ipAddress);
        return new BlockResult(true, "No external firewall - internal Redis unblock only", null);
    }

    @Override
    public boolean isAvailable() {
        return false;
    }

    @Override
    public String getVendorName() {
        return "NoOp";
    }
}
