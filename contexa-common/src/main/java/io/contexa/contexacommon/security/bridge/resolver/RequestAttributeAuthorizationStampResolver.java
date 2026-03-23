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

public class RequestAttributeAuthorizationStampResolver implements AuthorizationStampResolver {

    @Override
    public Optional<AuthorizationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        BridgeProperties.RequestAttributes config = properties.getAuthorization().getRequestAttributes();
        if (!config.isEnabled()) {
            return Optional.empty();
        }
        Object effect = request.getAttribute(config.getAuthorizationEffect());
        Object roles = request.getAttribute(config.getEffectiveRoles());
        Object authorities = request.getAttribute(config.getEffectiveAuthorities());
        Object privileged = request.getAttribute(config.getPrivileged());
        Object scopeTags = request.getAttribute(config.getScopeTags());
        if (effect == null && roles == null && authorities == null && privileged == null && scopeTags == null) {
            return Optional.empty();
        }
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("authorizationResolver", "REQUEST_ATTRIBUTE");
        return Optional.of(new AuthorizationStamp(
                resolveSubjectId(request),
                requestContext.requestUri(),
                requestContext.method(),
                AuthorizationEffect.from(effect),
                privileged instanceof Boolean booleanValue ? booleanValue : null,
                split(scopeTags),
                text(request.getAttribute(config.getPolicyId())),
                null,
                "REQUEST_ATTRIBUTE",
                Instant.now(),
                split(roles),
                split(authorities),
                attributes
        ));
    }

    private String resolveSubjectId(HttpServletRequest request) {
        return request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : null;
    }

    private List<String> split(Object raw) {
        if (raw == null) {
            return List.of();
        }
        String text = raw.toString();
        if (text.isBlank()) {
            return List.of();
        }
        return List.of(text.split("\\s*,\\s*"));
    }

    private String text(Object raw) {
        return raw != null ? raw.toString() : null;
    }
}
