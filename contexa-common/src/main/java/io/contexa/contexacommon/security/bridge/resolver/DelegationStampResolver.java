package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

public interface DelegationStampResolver {

    Optional<DelegationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties);
}
