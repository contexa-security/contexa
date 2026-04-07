package io.contexa.contexacore.autonomous.context.collector;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.Optional;
import io.contexa.contexacore.autonomous.context.collector.ProtectableWorkProfileSnapshot;

public interface ProtectableWorkProfileCollector {

    Optional<ProtectableWorkProfileSnapshot> collect(SecurityEvent event);
}
