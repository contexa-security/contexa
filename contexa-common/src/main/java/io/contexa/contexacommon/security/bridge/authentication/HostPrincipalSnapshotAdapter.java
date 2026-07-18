package io.contexa.contexacommon.security.bridge.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Copies only stable, non-credential host authentication facts into a Contexa-owned snapshot.
 */
public final class HostPrincipalSnapshotAdapter {

    public static final HostPrincipalSnapshotAdapter INSTANCE = new HostPrincipalSnapshotAdapter();

    private HostPrincipalSnapshotAdapter() {
    }

    public HostPrincipalSnapshot snapshot(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalArgumentException("authenticated host principal is required");
        }
        String principalId = authentication.getName();
        if (principalId == null || principalId.isBlank()) {
            throw new IllegalArgumentException("host authentication name is required");
        }
        Set<String> authorities = new LinkedHashSet<>();
        if (authentication.getAuthorities() != null) {
            authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .filter(value -> value != null && !value.isBlank())
                    .map(String::trim)
                    .forEach(authorities::add);
        }
        Map<String, Object> trustedAttributes = new LinkedHashMap<>();
        trustedAttributes.put("authenticationType", authentication.getClass().getName());
        Object principal = authentication.getPrincipal();
        if (principal != null) {
            trustedAttributes.put("principalType", principal.getClass().getName());
        }
        trustedAttributes.put("authenticated", true);
        return new HostPrincipalSnapshot(principalId, authorities, trustedAttributes);
    }
}