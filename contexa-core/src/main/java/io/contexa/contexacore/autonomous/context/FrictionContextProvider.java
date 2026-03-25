package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

public interface FrictionContextProvider {

    void enrich(SecurityEvent event, CanonicalSecurityContext context);
}
