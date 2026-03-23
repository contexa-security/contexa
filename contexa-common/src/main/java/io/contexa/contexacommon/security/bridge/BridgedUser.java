package io.contexa.contexacommon.security.bridge;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public record BridgedUser(
        String username,
        String displayName,
        Set<String> roles,
        Map<String, Object> attributes
) {

    public BridgedUser {
        roles = roles == null ? Set.of() : Set.copyOf(new LinkedHashSet<>(roles));
        attributes = attributes == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(attributes));
    }

    public BridgedUser(String username) {
        this(username, username, Set.of(), Map.of());
    }

    public BridgedUser(String username, Set<String> roles) {
        this(username, username, roles, Map.of());
    }
}
