package io.contexa.contexamcp.service;

import lombok.Builder;
import lombok.Data;

import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;

public interface IpBlockingService {

    BlockResult blockIp(String ipAddress, String reason, Duration duration, String blockedBy);

    @Data
    @Builder
    class BlockResult {
        private boolean success;
        private String ipAddress;
        private String message;
        private Instant blockedUntil;
    }

    @Data
    @Builder
    class BlockedIpInfo implements Serializable {
        private String ipAddress;
        private String reason;
        private Instant blockedAt;
        private Instant expiresAt;
        private String blockedBy;
        private boolean active;
    }
}
