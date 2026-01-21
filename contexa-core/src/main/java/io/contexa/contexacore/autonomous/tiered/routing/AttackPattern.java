package io.contexa.contexacore.autonomous.tiered.routing;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AttackPattern implements Serializable {
    
    private static final long serialVersionUID = 1L;

    private String sourceIp;

    private String pattern;

    private String attackType;

    private String severity;

    private LocalDateTime detectedAt;

    private LocalDateTime lastSeenAt;

    private int attemptCount;

    private boolean active;

    private LocalDateTime deactivatedAt;

    private boolean blocked;

    private LocalDateTime blockedAt;

    private LocalDateTime blockExpiresAt;

    private double confidenceScore;

    private String mitreTactic;
    private String mitreTechnique;

    private String metadata;

    public boolean isActive() {
        return active && !isExpired();
    }

    public boolean isExpired() {
        if (blockExpiresAt == null) {
            return false;
        }
        return LocalDateTime.now().isAfter(blockExpiresAt);
    }

    public boolean shouldBlock() {
        return blocked && isActive() && !isExpired();
    }

    public void incrementAttempt() {
        this.attemptCount++;
        this.lastSeenAt = LocalDateTime.now();
    }
}