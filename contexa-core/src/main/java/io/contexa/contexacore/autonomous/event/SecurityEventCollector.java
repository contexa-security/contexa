package io.contexa.contexacore.autonomous.event;

import java.util.Map;

/**
 * Abstraction for collecting and distributing security events to registered listeners.
 * Implementations: KafkaSecurityEventCollector (distributed), InMemorySecurityEventCollector (standalone).
 */
public interface SecurityEventCollector {

    void registerListener(SecurityEventListener listener);

    void unregisterListener(SecurityEventListener listener);

    Map<String, Object> getStatistics();
}
