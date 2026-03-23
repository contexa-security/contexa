package io.contexa.contexacommon.security.bridge.web;

import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageReport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;

public record BridgeResolutionResult(
        RequestContextSnapshot requestContext,
        AuthenticationStamp authenticationStamp,
        AuthorizationStamp authorizationStamp,
        DelegationStamp delegationStamp,
        BridgeCoverageReport coverageReport
) {
}
