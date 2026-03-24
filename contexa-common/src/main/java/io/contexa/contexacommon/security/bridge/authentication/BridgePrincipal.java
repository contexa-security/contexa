package io.contexa.contexacommon.security.bridge.authentication;

import java.io.Serializable;
import java.security.Principal;

public record BridgePrincipal(
        String username,
        String principalId,
        String displayName,
        String principalType,
        String organizationId,
        String orgId,
        String department,
        Long internalUserId,
        String bridgeSubjectKey,
        boolean bridgeManaged,
        boolean externalAuthOnly
) implements Principal, Serializable {

    @Override
    public String getName() {
        if (username != null && !username.isBlank()) {
            return username;
        }
        return principalId;
    }

    public String getExternalSubjectId() {
        return principalId;
    }
}
