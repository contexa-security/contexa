package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

public interface AuthenticationStampResolver {

    Optional<AuthenticationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties);
}
