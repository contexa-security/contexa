package io.contexa.contexacore.autonomous.event.listener;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.SecurityEventCollector;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory implementation of SecurityEventCollector for standalone mode.
 * Receives events directly from InMemorySecurityEventPublisher without Kafka.
 */
@Slf4j
public class InMemorySecurityEventCollector implements SecurityEventCollector {

    private static final int MAX_CACHE_SIZE = 10_000;
    private static final int EVICTION_BATCH = 1_000;

    private final List<SecurityEventListener> listeners = new CopyOnWriteArrayList<>();
    private final Map<String, SecurityEvent> eventCache = new ConcurrentHashMap<>();
    private final AtomicLong eventCount = new AtomicLong(0);
    private final AtomicLong errorCount = new AtomicLong(0);

    @Override
    public void registerListener(SecurityEventListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    @Override
    public void unregisterListener(SecurityEventListener listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    @Override
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("total_events", eventCount.get());
        stats.put("error_count", errorCount.get());
        stats.put("cache_size", eventCache.size());
        stats.put("listener_count", listeners.size());
        return stats;
    }

    /**
     * Dispatches a security event to all registered listeners.
     * Called by InMemorySecurityEventPublisher.
     */
    public void dispatchEvent(SecurityEvent event) {
        if (event == null) {
            return;
        }

        eventCount.incrementAndGet();

        if (event.getEventId() != null) {
            if (eventCache.size() >= MAX_CACHE_SIZE) {
                evictOldEntries();
            }
            eventCache.put(event.getEventId(), event);
        }

        for (SecurityEventListener listener : listeners) {
            try {
                if (listener.isActive()) {
                    listener.onSecurityEvent(event);
                }
            } catch (Exception e) {
                errorCount.incrementAndGet();
                log.error("Failed to dispatch event to listener: {}", listener.getListenerName(), e);
            }
        }
    }

    private void evictOldEntries() {
        eventCache.keySet().stream()
                .limit(EVICTION_BATCH)
                .toList()
                .forEach(eventCache::remove);
    }
}
