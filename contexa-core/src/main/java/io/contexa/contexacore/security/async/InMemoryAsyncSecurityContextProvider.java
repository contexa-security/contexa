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
package io.contexa.contexacore.security.async;

import io.contexa.contexacore.autonomous.store.ExpiringKeySpace;
import io.contexa.contexacore.autonomous.store.ExpiringStateStore;
import lombok.extern.slf4j.Slf4j;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * In-memory copies of authentications for asynchronous work. Z-16 (F7): as in the Redis provider, each record is a copy
 * of its own (a Redis key holds its own serialized value), and a refresh keeps the user's record and the session's two
 * records another day while it rewrites only the user's. The records are {@link ExpiringKeySpace}s (N-1) of 10,000
 * keys each, the record written the longest ago going first past them, as Redis {@code volatile-ttl} evicts. The sweep
 * releases the records past their day.
 */
@Slf4j
public class InMemoryAsyncSecurityContextProvider extends AbstractAsyncSecurityContextProvider
        implements ExpiringStateStore {

    private static final int MAX_RECORDS = 10_000;

    private final ExpiringKeySpace<AsyncAuthenticationData> userStore;
    private final ExpiringKeySpace<AsyncAuthenticationData> compositeStore;
    private final ExpiringKeySpace<String> sessionToUserStore;

    public InMemoryAsyncSecurityContextProvider() {
        this(Clock.systemUTC());
    }

    /** Measures the records' time with {@code clock}. */
    InMemoryAsyncSecurityContextProvider(Clock clock) {
        this.userStore = ExpiringKeySpace.<AsyncAuthenticationData>builder(clock)
                .ttl(DEFAULT_TTL)
                .bound(MAX_RECORDS)
                .build();
        this.compositeStore = ExpiringKeySpace.<AsyncAuthenticationData>builder(clock)
                .ttl(DEFAULT_TTL)
                .bound(MAX_RECORDS)
                .build();
        this.sessionToUserStore = ExpiringKeySpace.<String>builder(clock)
                .ttl(DEFAULT_TTL)
                .bound(MAX_RECORDS)
                .build();
    }

    @Override
    protected void doSave(String userId, String sessionId, AsyncAuthenticationData data) {
        userStore.put(userId, copyOf(data));

        if (sessionId != null) {
            compositeStore.put(userId + ":" + sessionId, copyOf(data));
            sessionToUserStore.put(sessionId, userId);
        }
    }

    private static AsyncAuthenticationData copyOf(AsyncAuthenticationData data) {
        return AsyncAuthenticationData.builder()
                .userId(data.getUserId())
                .sessionId(data.getSessionId())
                .principalType(data.getPrincipalType())
                .authorities(data.getAuthorities() != null ? List.copyOf(data.getAuthorities()) : null)
                .createdAt(data.getCreatedAt())
                .expiresAt(data.getExpiresAt())
                .build();
    }

    @Override
    public Optional<AsyncAuthenticationData> getAuthenticationByUserId(String userId) {
        if (userId == null || userId.isEmpty()) {
            return Optional.empty();
        }

        AsyncAuthenticationData data = userStore.get(userId);
        if (data != null && data.isValid()) {
            return Optional.of(data);
        }
        return Optional.empty();
    }

    @Override
    public Optional<AsyncAuthenticationData> getAuthenticationBySessionId(String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) {
            return Optional.empty();
        }

        String userId = sessionToUserStore.get(sessionId);
        if (userId != null) {
            AsyncAuthenticationData data = compositeStore.get(userId + ":" + sessionId);
            if (data != null && data.isValid()) {
                return Optional.of(data);
            }
            return getAuthenticationByUserId(userId);
        }
        return Optional.empty();
    }

    @Override
    public void removeAuthentication(String userId, String sessionId) {
        if (userId != null) {
            userStore.remove(userId);
        }
        if (userId != null && sessionId != null) {
            compositeStore.remove(userId + ":" + sessionId);
        }
        if (sessionId != null) {
            sessionToUserStore.remove(sessionId);
        }
    }

    @Override
    public void removeExpiredEntries() {
        userStore.removeExpired();
        compositeStore.removeExpired();
        sessionToUserStore.removeExpired();
    }

    @Override
    public void refreshExpiration(String userId, String sessionId) {
        if (userId == null) {
            return;
        }

        AsyncAuthenticationData data = userStore.get(userId);
        if (data != null) {
            data.setExpiresAt(Instant.now().plus(DEFAULT_TTL));
            userStore.put(userId, data);

            if (sessionId != null) {
                // Kept as they are another day, as the Redis provider extends their keys.
                compositeStore.getAndRefresh(userId + ":" + sessionId);
                sessionToUserStore.getAndRefresh(sessionId);
            }
        }
    }
}
