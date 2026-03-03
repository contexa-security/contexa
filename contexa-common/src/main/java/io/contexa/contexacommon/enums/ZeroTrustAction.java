package io.contexa.contexacommon.enums;

import java.time.Duration;

public enum ZeroTrustAction {

    ALLOW(200, 1500, null),

    BLOCK(403, -1, "ROLE_BLOCKED"),

    CHALLENGE(401, 1800, "ROLE_MFA_REQUIRED"),

    ESCALATE(423, 300, "ROLE_REVIEW_REQUIRED"),

    PENDING_ANALYSIS(503, 0, "ROLE_PENDING_ANALYSIS");

    private final int httpStatus;
    private final long defaultTtlSeconds;
    private final String grantedAuthority;

    ZeroTrustAction(int httpStatus, long defaultTtlSeconds, String grantedAuthority) {
        this.httpStatus = httpStatus;
        this.defaultTtlSeconds = defaultTtlSeconds;
        this.grantedAuthority = grantedAuthority;
    }

    public static ZeroTrustAction fromString(String action) {
        if (action == null || action.isBlank()) {
            return ESCALATE;
        }

        return switch (action.trim().toUpperCase()) {
            case "ALLOW", "A" -> ALLOW;
            case "BLOCK", "B" -> BLOCK;
            case "CHALLENGE", "C" -> CHALLENGE;
            case "ESCALATE", "E" -> ESCALATE;
            case "PENDING_ANALYSIS" -> PENDING_ANALYSIS;
            default -> ESCALATE;
        };
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public Duration getDefaultTtl() {
        if (defaultTtlSeconds <= 0) {
            return null;
        }
        return Duration.ofSeconds(defaultTtlSeconds);
    }

    public boolean isBlocking() {
        return this == BLOCK || this == ESCALATE;
    }

    public boolean isAccessRestricted() {
        return this == BLOCK || this == CHALLENGE || this == ESCALATE;
    }

    public String getGrantedAuthority() {
        return grantedAuthority;
    }
}
