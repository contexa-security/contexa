package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

public interface AuthenticationContextProvider {

    void enrich(SecurityEvent event, CanonicalSecurityContext context);
}
