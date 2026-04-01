package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.List;

public interface BatchSecurityEventListener {

    default String getListenerName() {
        return this.getClass().getSimpleName();
    }

    void onBatchEvents(List<SecurityEvent> events);

    default boolean isActive() {
        return true;
    }
}
