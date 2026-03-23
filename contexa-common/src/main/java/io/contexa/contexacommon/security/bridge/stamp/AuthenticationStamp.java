package io.contexa.contexacommon.security.bridge.stamp;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public record AuthenticationStamp(
        String principalId,
        String displayName,
        String principalType,
        boolean authenticated,
        String authenticationType,
        String authenticationSource,
        String authenticationAssurance,
        Boolean mfaCompleted,
        Instant authenticationTime,
        String sessionId,
        List<String> authorities,
        Map<String, Object> attributes
) {

    public AuthenticationStamp {
        authorities = authorities == null ? List.of() : List.copyOf(new LinkedHashSet<>(authorities));
        attributes = attributes == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(attributes));
    }
}
