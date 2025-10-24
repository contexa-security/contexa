package io.contexa.contexaiam.common.event.service;

import io.contexa.contexaiam.common.event.dto.DomainEvent;

@FunctionalInterface
public interface EventHandler<T extends DomainEvent> {
    void handle(T event);
}
