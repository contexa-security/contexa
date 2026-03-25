package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.Optional;

public interface ProtectableWorkProfileCollector {

    Optional<ProtectableWorkProfileSnapshot> collect(SecurityEvent event);
}
