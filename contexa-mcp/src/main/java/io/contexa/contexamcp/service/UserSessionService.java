package io.contexa.contexamcp.service;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;

public interface UserSessionService {

    List<SessionInfo> findActiveSessionsByUserId(String userId);

    boolean terminateSession(String sessionId);

    @Data
    @Builder
    class SessionInfo {
        private String sessionId;
        private String userId;
        private String ipAddress;
        private String userAgent;
        private Instant createdAt;
        private Instant lastAccessedAt;
        private Instant terminatedAt;
        private boolean active;
    }
}
