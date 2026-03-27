package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.Optional;

public interface RoleScopeCollector {

    Optional<RoleScopeSnapshot> collect(SecurityEvent event);
}
