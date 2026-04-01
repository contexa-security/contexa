package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacore.autonomous.event.SecurityEventCollector;
import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.InMemorySecurityEventCollector;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * In-memory implementation of SecurityEventPublisher for standalone mode.
 * Dispatches events directly to InMemorySecurityEventCollector without Kafka.
 */
@Slf4j
@RequiredArgsConstructor
public class InMemorySecurityEventPublisher implements SecurityEventPublisher {

    private final SecurityEventCollector eventCollector;

    @Override
    public void publishGenericSecurityEvent(ZeroTrustSpringEvent event) {
        if (event == null) {
            return;
        }

        try {
            var securityEvent = ZeroTrustSecurityEventConverter.convert(event);
            if (eventCollector instanceof InMemorySecurityEventCollector inMemoryCollector) {
                inMemoryCollector.dispatchEvent(securityEvent);
            }
        } catch (Exception e) {
            log.error("Failed to publish in-memory security event: userId={}", event.getUserId(), e);
        }
    }
}
