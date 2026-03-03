package io.contexa.contexacore.hcad.store;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryHCADDataStore implements HCADDataStore {

    private static final int MAX_DEVICES = 10;

    private final ConcurrentHashMap<String, Map<String, Object>> sessionMetadata = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Set<String>> userDevices = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, TreeMap<Long, String>> requestCounters = new ConcurrentHashMap<>();
    private final Set<String> registeredUsers = ConcurrentHashMap.newKeySet();
    private final Set<String> mfaVerifiedUsers = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, Map<Object, Object>> hcadAnalysis = new ConcurrentHashMap<>();

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
        return devices != null && devices.contains(device);
    }

    @Override
    public void registerDevice(String userId, String device) {
        userDevices.compute(userId, (key, devices) -> {
            if (devices == null) {
                devices = ConcurrentHashMap.newKeySet();
            }
            devices.add(device);
            if (devices.size() > MAX_DEVICES) {
                Iterator<String> it = devices.iterator();
                String first = it.next();
                if (!first.equals(device)) {
                    it.remove();
                }
            }
            return devices;
        });
    }

    @Override
    public void recordRequest(String userId, long currentTimeMs) {
        requestCounters.compute(userId, (key, counter) -> {
            if (counter == null) {
                counter = new TreeMap<>();
            }
            counter.put(currentTimeMs, Long.toString(currentTimeMs));
            long fiveMinutesAgo = currentTimeMs - (5 * 60 * 1000);
            counter.headMap(fiveMinutesAgo).clear();
            return counter;
        });
    }

    @Override
    public int getRecentRequestCount(String userId, long windowStartMs, long currentTimeMs) {
        TreeMap<Long, String> counter = requestCounters.get(userId);
        if (counter == null) {
            return 0;
        }
        synchronized (counter) {
            return counter.subMap(windowStartMs, true, currentTimeMs, true).size();
        }
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
        return mfaVerifiedUsers.contains(userId);
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
}
