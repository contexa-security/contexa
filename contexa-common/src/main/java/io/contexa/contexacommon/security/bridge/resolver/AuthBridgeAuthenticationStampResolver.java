package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.AuthBridge;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgedUser;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Optional;

public class AuthBridgeAuthenticationStampResolver implements AuthenticationStampResolver {

    private final AuthBridge authBridge;

    public AuthBridgeAuthenticationStampResolver(AuthBridge authBridge) {
        this.authBridge = authBridge;
    }

    @Override
    public Optional<AuthenticationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        if (authBridge == null) {
            return Optional.empty();
        }
        BridgedUser bridgedUser = authBridge.extractUser(request);
        if (bridgedUser == null || bridgedUser.username() == null || bridgedUser.username().isBlank()) {
            return Optional.empty();
        }
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>(bridgedUser.attributes());
        Instant authenticationTime = null;
        Object authTime = attributes.get("authenticationTime");
        if (authTime instanceof Instant instant) {
            authenticationTime = instant;
        }
        Boolean mfaCompleted = null;
        Object mfa = attributes.get("mfaCompleted");
        if (mfa instanceof Boolean booleanValue) {
            mfaCompleted = booleanValue;
        }
        return Optional.of(new AuthenticationStamp(
                bridgedUser.username(),
                bridgedUser.displayName(),
                "BRIDGED_USER",
                true,
                String.valueOf(attributes.getOrDefault("authenticationType", "BRIDGE")),
                String.valueOf(attributes.getOrDefault("bridgeAuthenticationSource", authBridge.getClass().getSimpleName())),
                String.valueOf(attributes.getOrDefault("authenticationAssurance", "STANDARD")),
                mfaCompleted,
                authenticationTime,
                requestContext.sessionId(),
                bridgedUser.roles().stream().toList(),
                attributes
        ));
    }
}

