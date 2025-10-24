package io.contexa.contexaiam.common.event.service;

import io.contexa.contexaiam.common.event.dto.DomainEvent;

public interface IntegrationEventBus {
    void publish(DomainEvent event);
    <T extends DomainEvent> void subscribe(Class<T> eventType, EventHandler<T> handler);
}