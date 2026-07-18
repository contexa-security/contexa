package io.contexa.contexacommon.security.bridge.authentication;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Immutable, read-only view of a host application's authenticated principal.
 */
public record HostPrincipalSnapshot(
        String principalId,
        Set<String> authorities,
        Map<String, Object> trustedAttributes
) implements Serializable {

    public HostPrincipalSnapshot {
        if (principalId == null || principalId.isBlank()) {
            throw new IllegalArgumentException("host principalId is required");
        }
        principalId = principalId.trim();
        authorities = authorities == null || authorities.isEmpty()
                ? Set.of()
                : Set.copyOf(new LinkedHashSet<>(authorities));
        trustedAttributes = trustedAttributes == null || trustedAttributes.isEmpty()
                ? Map.of()
                : Map.copyOf(new LinkedHashMap<>(trustedAttributes));
    }
}