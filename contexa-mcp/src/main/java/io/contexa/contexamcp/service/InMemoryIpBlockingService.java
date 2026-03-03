package io.contexa.contexamcp.service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryIpBlockingService extends AbstractIpBlockingService {

    private final Map<String, BlockedIpInfo> blockedIps = new ConcurrentHashMap<>();
    private final Set<String> whitelistedIps = ConcurrentHashMap.newKeySet();

    @Override
    protected boolean doIsWhitelisted(String ipAddress) {
        return whitelistedIps.contains(ipAddress);
    }

    @Override
    protected boolean doIsBlocked(String ipAddress) {
        BlockedIpInfo existing = blockedIps.get(ipAddress);
        if (existing != null && existing.isActive()) {
            return existing.getExpiresAt() == null || existing.getExpiresAt().isAfter(Instant.now());
        }
        return false;
    }

    @Override
    protected void doBlockIp(String ipAddress, BlockedIpInfo info, Duration duration) {
        blockedIps.put(ipAddress, info);
    }
}
