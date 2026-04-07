package io.contexa.contexacore.autonomous.context.collector;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.Optional;
import io.contexa.contexacore.autonomous.context.collector.RoleScopeSnapshot;

public interface RoleScopeCollector {

    Optional<RoleScopeSnapshot> collect(SecurityEvent event);
}
