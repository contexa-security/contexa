package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

public interface AuthorizationSnapshotProvider {

    void enrich(SecurityEvent event, CanonicalSecurityContext context);
}
