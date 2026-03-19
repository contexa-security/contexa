package io.contexa.contexacommon.security.bridge;

import java.util.Map;
import java.util.Set;

/**
 * Represents a user identity extracted from a legacy authentication system.
 * This is a read-only snapshot of the legacy user's current state.
 *
 * @param username    unique user identifier (required)
 * @param displayName human-readable name (optional)
 * @param roles       legacy role names, e.g. {"ADMIN", "MANAGER"} (optional)
 * @param attributes  arbitrary key-value pairs from the legacy session (optional)
 */
public record BridgedUser(
        String username,
        String displayName,
        Set<String> roles,
        Map<String, Object> attributes
) {

    /**
     * Minimal constructor with username only.
     */
    public BridgedUser(String username) {
        this(username, username, Set.of(), Map.of());
    }

    /**
     * Constructor with username and roles.
     */
    public BridgedUser(String username, Set<String> roles) {
        this(username, username, roles, Map.of());
    }
}
