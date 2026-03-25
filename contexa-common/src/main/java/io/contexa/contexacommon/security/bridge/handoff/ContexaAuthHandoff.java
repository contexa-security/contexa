package io.contexa.contexacommon.security.bridge.handoff;

import org.springframework.lang.Nullable;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;

public record ContexaAuthHandoff(
        Object principal,
        Collection<?> authorities,
        Map<String, Object> attributes,
        String authenticationType,
        String authenticationAssurance,
        Boolean mfaVerified
) {

    public ContexaAuthHandoff {
        if (principal == null) {
            throw new IllegalArgumentException("principal must not be null");
        }
        authorities = authorities == null ? java.util.List.of() : java.util.List.copyOf(new LinkedHashSet<>(authorities));
        attributes = attributes == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(attributes));
    }

    public static ContexaAuthHandoff of(Object principal) {
        return new ContexaAuthHandoff(principal, java.util.List.of(), Map.of(), null, null, null);
    }

    public static ContexaAuthHandoff of(Object principal, Collection<?> authorities) {
        return new ContexaAuthHandoff(principal, authorities, Map.of(), null, null, null);
    }

    public static ContexaAuthHandoff of(Object principal, Collection<?> authorities, Map<String, Object> attributes) {
        return new ContexaAuthHandoff(principal, authorities, attributes, null, null, null);
    }

    public ContexaAuthHandoff withAuthenticationType(@Nullable String authenticationType) {
        return new ContexaAuthHandoff(principal, authorities, attributes, authenticationType, authenticationAssurance, mfaVerified);
    }

    public ContexaAuthHandoff withAuthenticationAssurance(@Nullable String authenticationAssurance) {
        return new ContexaAuthHandoff(principal, authorities, attributes, authenticationType, authenticationAssurance, mfaVerified);
    }

    public ContexaAuthHandoff withMfaVerified(@Nullable Boolean mfaVerified) {
        return new ContexaAuthHandoff(principal, authorities, attributes, authenticationType, authenticationAssurance, mfaVerified);
    }
}