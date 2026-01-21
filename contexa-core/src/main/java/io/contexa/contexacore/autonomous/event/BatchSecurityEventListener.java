package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.List;

public interface BatchSecurityEventListener extends SecurityEventListener {

    @Override
    void onBatchEvents(List<SecurityEvent> events);

    @Override
    default void onSecurityEvent(SecurityEvent event) {
        onBatchEvents(List.of(event));
    }
}
