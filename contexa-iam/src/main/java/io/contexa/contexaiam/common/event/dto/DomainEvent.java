package io.contexa.contexaiam.common.event.dto;

import java.time.LocalDateTime;

public abstract class DomainEvent {
    private final LocalDateTime occurredOn = LocalDateTime.now();
    public LocalDateTime getOccurredOn() { return occurredOn; }
}