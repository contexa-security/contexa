package io.contexa.contexacore.autonomous.telemetry;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

public final class SecurityEventTelemetryContext {

    private static final ThreadLocal<SecurityEvent> CURRENT_EVENT = new ThreadLocal<>();

    private SecurityEventTelemetryContext() {
    }

    public static Scope open(SecurityEvent event) {
        CURRENT_EVENT.set(event);
        return () -> CURRENT_EVENT.remove();
    }

    public static void put(String key, Object value) {
        SecurityEvent event = CURRENT_EVENT.get();
        if (event != null && key != null && !key.isBlank()) {
            event.addMetadata(key, value);
        }
    }

    public static void putIfAbsent(String key, Object value) {
        SecurityEvent event = CURRENT_EVENT.get();
        if (event == null || key == null || key.isBlank()) {
            return;
        }
        if (event.getMetadata() == null || !event.getMetadata().containsKey(key)) {
            event.addMetadata(key, value);
        }
    }

    public static void increment(String key) {
        incrementBy(key, 1L);
    }

    public static void incrementBy(String key, long delta) {
        SecurityEvent event = CURRENT_EVENT.get();
        if (event == null || key == null || key.isBlank()) {
            return;
        }
        long current = 0L;
        Object existing = event.getMetadata() != null ? event.getMetadata().get(key) : null;
        if (existing instanceof Number number) {
            current = number.longValue();
        } else if (existing instanceof String stringValue) {
            try {
                current = Long.parseLong(stringValue);
            } catch (NumberFormatException ignored) {
                current = 0L;
            }
        }
        event.addMetadata(key, current + delta);
    }

    public interface Scope extends AutoCloseable {
        @Override
        void close();
    }
}
