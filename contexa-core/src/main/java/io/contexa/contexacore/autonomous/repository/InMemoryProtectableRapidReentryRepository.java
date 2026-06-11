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
package io.contexa.contexacore.autonomous.repository;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryProtectableRapidReentryRepository implements ProtectableRapidReentryRepository {

    private final ConcurrentHashMap<String, Instant> reentryWindows = new ConcurrentHashMap<>();

    @Override
    public boolean tryAcquire(String userId, String contextBindingHash, String resourceKey, Duration window) {
        if (isInvalid(userId) || isInvalid(contextBindingHash) || isInvalid(resourceKey) || window == null) {
            return true;
        }

        Instant now = Instant.now();
        Instant expiresAt = now.plus(window);
        String key = buildKey(userId, contextBindingHash, resourceKey);

        while (true) {
            Instant existing = reentryWindows.get(key);
            if (existing != null) {
                if (existing.isAfter(now)) {
                    return false;
                }
                if (!reentryWindows.remove(key, existing)) {
                    continue;
                }
            }

            Instant previous = reentryWindows.putIfAbsent(key, expiresAt);
            if (previous == null) {
                return true;
            }
            if (previous.isAfter(now)) {
                return false;
            }
            reentryWindows.remove(key, previous);
        }
    }

    private String buildKey(String userId, String contextBindingHash, String resourceKey) {
        return userId + "\u0000" + contextBindingHash + "\u0000" + resourceKey;
    }

    private boolean isInvalid(String value) {
        return value == null || value.isBlank();
    }
}
