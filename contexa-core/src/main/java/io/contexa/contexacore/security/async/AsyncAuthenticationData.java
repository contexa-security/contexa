package io.contexa.contexacore.security.async;

import lombok.Builder;
import lombok.Data;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.List;

@Data
@Builder
public class AsyncAuthenticationData implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private String userId;
    private String sessionId;
    private String principalType;
    private List<String> authorities;
    private Instant createdAt;
    private Instant expiresAt;

    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    public boolean isValid() {
        return userId != null && !userId.isEmpty() && !isExpired();
    }
}
