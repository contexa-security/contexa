package io.contexa.contexacommon.security.bridge.stamp;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public record AuthorizationStamp(
        String subjectId,
        String resourceId,
        String action,
        AuthorizationEffect effect,
        Boolean privileged,
        List<String> scopeTags,
        String policyId,
        String policyVersion,
        String decisionSource,
        Instant decisionTime,
        List<String> effectiveRoles,
        List<String> effectiveAuthorities,
        Map<String, Object> attributes
) {

    public AuthorizationStamp {
        effect = effect == null ? AuthorizationEffect.UNKNOWN : effect;
        scopeTags = scopeTags == null ? List.of() : List.copyOf(new LinkedHashSet<>(scopeTags));
        effectiveRoles = effectiveRoles == null ? List.of() : List.copyOf(new LinkedHashSet<>(effectiveRoles));
        effectiveAuthorities = effectiveAuthorities == null ? List.of() : List.copyOf(new LinkedHashSet<>(effectiveAuthorities));
        attributes = attributes == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(attributes));
    }
}
