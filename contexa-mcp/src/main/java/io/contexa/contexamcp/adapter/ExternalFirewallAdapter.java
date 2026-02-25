package io.contexa.contexamcp.adapter;

/**
 * Adapter interface for external firewall integration.
 * Implementations connect to vendor-specific APIs (Palo Alto, Fortinet, AWS Security Group, etc.).
 * Default: NoOpFirewallAdapter (internal Redis-only blocking).
 */
public interface ExternalFirewallAdapter {

    BlockResult blockIp(String ipAddress, String reason, Integer durationMinutes);

    BlockResult unblockIp(String ipAddress, String reason);

    boolean isAvailable();

    String getVendorName();

    record BlockResult(boolean success, String message, String ruleId) {
    }
}
