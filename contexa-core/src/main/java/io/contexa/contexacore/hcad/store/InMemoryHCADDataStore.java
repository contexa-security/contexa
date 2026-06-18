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
package io.contexa.contexacore.hcad.store;

import java.time.Clock;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicLong;

public class InMemoryHCADDataStore implements HCADDataStore {

    private static final int MAX_DEVICES = 10;
    private static final Duration DEFAULT_MFA_VERIFIED_TTL = Duration.ofHours(1);
    private static final long REQUEST_COUNTER_KEY_FACTOR = 1_000_000L;

    private final ConcurrentHashMap<String, Map<String, Object>> sessionMetadata = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Set<String>> userDevices = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ConcurrentSkipListMap<Long, String>> requestCounters = new ConcurrentHashMap<>();
    private final AtomicLong requestSequence = new AtomicLong();
    private final Set<String> registeredUsers = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, Long> mfaVerifiedExpiry = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Map<Object, Object>> hcadAnalysis = new ConcurrentHashMap<>();

    private final Duration mfaVerifiedTtl;
    private final Clock clock;

    public InMemoryHCADDataStore() {
        this(DEFAULT_MFA_VERIFIED_TTL, Clock.systemUTC());
    }

    public InMemoryHCADDataStore(Duration mfaVerifiedTtl) {
        this(mfaVerifiedTtl, Clock.systemUTC());
    }

    public InMemoryHCADDataStore(Duration mfaVerifiedTtl, Clock clock) {
        this.mfaVerifiedTtl = Objects.requireNonNull(mfaVerifiedTtl, "mfaVerifiedTtl");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public Map<Object, Object> getSessionMetadata(String sessionId) {
        Map<String, Object> metadata = sessionMetadata.get(sessionId);
        if (metadata == null) {
            return new HashMap<>();
        }
        return new HashMap<>(metadata);
    }

    @Override
    public void saveSessionMetadata(String sessionId, Map<String, Object> metadata) {
        sessionMetadata.put(sessionId, new ConcurrentHashMap<>(metadata));
    }

    @Override
    public boolean isDeviceRegistered(String userId, String device) {
        Set<String> devices = userDevices.get(userId);
        if (devices == null) {
            return false;
        }
        synchronized (devices) {
            return devices.contains(device);
        }
    }

    @Override
    public void registerDevice(String userId, String device) {
        userDevices.compute(userId, (key, devices) -> {
            Set<String> orderedDevices = devices != null ? devices : new LinkedHashSet<>();
            synchronized (orderedDevices) {
                orderedDevices.remove(device);
                orderedDevices.add(device);
                while (orderedDevices.size() > MAX_DEVICES) {
                    Iterator<String> it = orderedDevices.iterator();
                    it.next();
                    it.remove();
                }
            }
            return orderedDevices;
        });
    }

    @Override
    public void recordRequest(String userId, long currentTimeMs) {
        requestCounters.compute(userId, (key, counter) -> {
            if (counter == null) {
                counter = new ConcurrentSkipListMap<>();
            }
            long uniqueKey = toCounterKey(currentTimeMs, requestSequence.incrementAndGet());
            counter.put(uniqueKey, Long.toString(currentTimeMs));
            long fiveMinutesAgo = currentTimeMs - (5 * 60 * 1000);
            counter.headMap(toCounterKey(fiveMinutesAgo, 0)).clear();
            return counter;
        });
    }

    @Override
    public int getRecentRequestCount(String userId, long windowStartMs, long currentTimeMs) {
        ConcurrentSkipListMap<Long, String> counter = requestCounters.get(userId);
        if (counter == null) {
            return 0;
        }
        return counter.subMap(
                toCounterKey(windowStartMs, 0),
                true,
                toCounterKey(currentTimeMs, REQUEST_COUNTER_KEY_FACTOR - 1),
                true).size();
    }

    @Override
    public boolean isUserRegistered(String userId) {
        return registeredUsers.contains(userId);
    }

    @Override
    public void registerUser(String userId) {
        registeredUsers.add(userId);
    }

    @Override
    public boolean isMfaVerified(String userId) {
        Long expiresAt = mfaVerifiedExpiry.get(userId);
        if (expiresAt == null) {
            return false;
        }
        if (clock.millis() >= expiresAt) {
            mfaVerifiedExpiry.remove(userId, expiresAt);
            return false;
        }
        return true;
    }

    @Override
    public void markMfaVerified(String userId) {
        mfaVerifiedExpiry.put(userId, clock.millis() + mfaVerifiedTtl.toMillis());
    }

    @Override
    public Map<Object, Object> getHcadAnalysis(String userId) {
        Map<Object, Object> analysis = hcadAnalysis.get(userId);
        return analysis != null ? new HashMap<>(analysis) : new HashMap<>();
    }

    @Override
    public void saveHcadAnalysis(String userId, Map<String, Object> analysisData) {
        Map<Object, Object> converted = new HashMap<>(analysisData);
        hcadAnalysis.put(userId, converted);
    }

    private long toCounterKey(long timestampMs, long sequence) {
        long sequenceSlot = Math.floorMod(sequence, REQUEST_COUNTER_KEY_FACTOR);
        return Math.addExact(Math.multiplyExact(timestampMs, REQUEST_COUNTER_KEY_FACTOR), sequenceSlot);
    }
}
