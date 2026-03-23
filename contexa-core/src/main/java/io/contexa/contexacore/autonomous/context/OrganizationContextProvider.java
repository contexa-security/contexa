package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

public interface OrganizationContextProvider {

    void enrich(SecurityEvent event, CanonicalSecurityContext context);
}
