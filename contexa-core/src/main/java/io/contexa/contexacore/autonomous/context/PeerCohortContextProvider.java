package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

public interface PeerCohortContextProvider {

    void enrich(SecurityEvent event, CanonicalSecurityContext context);
}
