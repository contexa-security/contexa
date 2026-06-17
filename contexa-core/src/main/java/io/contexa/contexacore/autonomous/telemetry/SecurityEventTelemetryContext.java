/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.telemetry;

import io.contexa.contexacore.SecurityEvent;

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
