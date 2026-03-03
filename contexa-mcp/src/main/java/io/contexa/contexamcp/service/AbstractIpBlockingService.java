package io.contexa.contexamcp.service;

import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.Instant;

@Slf4j
public abstract class AbstractIpBlockingService implements IpBlockingService {

    @Override
    public BlockResult blockIp(String ipAddress, String reason, Duration duration, String blockedBy) {
        try {
            if (doIsWhitelisted(ipAddress)) {
                return BlockResult.builder()
                        .success(false)
                        .ipAddress(ipAddress)
                        .message("IP is whitelisted and cannot be blocked")
                        .build();
            }

            if (doIsBlocked(ipAddress)) {
                return BlockResult.builder()
                        .success(false)
                        .ipAddress(ipAddress)
                        .message("IP is already blocked")
                        .build();
            }

            BlockedIpInfo blockInfo = BlockedIpInfo.builder()
                    .ipAddress(ipAddress)
                    .reason(reason)
                    .blockedAt(Instant.now())
                    .expiresAt(duration != null ? Instant.now().plus(duration) : null)
                    .blockedBy(blockedBy)
                    .active(true)
                    .build();

            doBlockIp(ipAddress, blockInfo, duration);

            return BlockResult.builder()
                    .success(true)
                    .ipAddress(ipAddress)
                    .message("IP successfully blocked")
                    .blockedUntil(blockInfo.getExpiresAt())
                    .build();

        } catch (Exception e) {
            log.error("Failed to block IP: {}", ipAddress, e);
            return BlockResult.builder()
                    .success(false)
                    .ipAddress(ipAddress)
                    .message("Failed to block IP: " + e.getMessage())
                    .build();
        }
    }

    protected abstract boolean doIsWhitelisted(String ipAddress);

    protected abstract boolean doIsBlocked(String ipAddress);

    protected abstract void doBlockIp(String ipAddress, BlockedIpInfo info, Duration duration);
}
