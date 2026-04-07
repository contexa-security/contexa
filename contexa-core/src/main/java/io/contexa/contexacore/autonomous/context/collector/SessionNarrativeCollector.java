package io.contexa.contexacore.autonomous.context.collector;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.Optional;
import io.contexa.contexacore.autonomous.context.collector.SessionNarrativeSnapshot;

public interface SessionNarrativeCollector {

    Optional<SessionNarrativeSnapshot> collect(SecurityEvent event);
}
