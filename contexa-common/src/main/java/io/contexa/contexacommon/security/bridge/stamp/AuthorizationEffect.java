package io.contexa.contexacommon.security.bridge.stamp;

public enum AuthorizationEffect {
    ALLOW,
    DENY,
    UNKNOWN;

    public static AuthorizationEffect from(Object raw) {
        if (raw == null) {
            return UNKNOWN;
        }
        String value = raw.toString().trim();
        if (value.isEmpty()) {
            return UNKNOWN;
        }
        return switch (value.toUpperCase()) {
            case "ALLOW", "ALLOWED", "PERMIT", "PERMITTED", "TRUE" -> ALLOW;
            case "DENY", "DENIED", "BLOCK", "BLOCKED", "FALSE" -> DENY;
            default -> UNKNOWN;
        };
    }
}
