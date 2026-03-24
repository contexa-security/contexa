package io.contexa.contexacommon.security.bridge.authentication;

import java.io.Serializable;
import java.security.Principal;

public record BridgePrincipal(
        String principalId,
        String displayName,
        String principalType,
        String organizationId,
        String orgId,
        String department
) implements Principal, Serializable {

    @Override
    public String getName() {
        return principalId;
    }
}
