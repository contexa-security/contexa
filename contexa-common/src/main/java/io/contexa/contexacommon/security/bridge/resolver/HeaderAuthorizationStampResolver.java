package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;

public class HeaderAuthorizationStampResolver implements AuthorizationStampResolver {

    @Override
    public Optional<AuthorizationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        BridgeProperties.Headers config = properties.getAuthorization().getHeaders();
        if (!config.isEnabled()) {
            return Optional.empty();
        }
        String effect = request.getHeader(config.getAuthorizationEffect());
        String roles = request.getHeader(config.getEffectiveRoles());
        String authorities = request.getHeader(config.getEffectiveAuthorities());
        String privileged = request.getHeader(config.getPrivileged());
        String scopeTags = request.getHeader(config.getScopeTags());
        String policyVersion = request.getHeader(config.getPolicyVersion());
        if (effect == null && roles == null && authorities == null && privileged == null && scopeTags == null && policyVersion == null) {
            return Optional.empty();
        }
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("authorizationResolver", "HEADER");
        return Optional.of(new AuthorizationStamp(
                SecurityContextStampSupport.resolveSubjectIdFromHeaders(request, properties),
                requestContext.requestUri(),
                requestContext.method(),
                AuthorizationEffect.from(effect),
                privileged != null ? Boolean.parseBoolean(privileged) : null,
                split(scopeTags),
                request.getHeader(config.getPolicyId()),
                policyVersion,
                "HEADER",
                Instant.now(),
                split(roles),
                split(authorities),
                attributes
        ));
    }

    private List<String> split(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        return List.of(raw.split("\\s*,\\s*"));
    }
}
