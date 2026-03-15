package io.contexa.contexacore.hcad.store;

import java.util.Map;

public interface HCADDataStore {

    Map<Object, Object> getSessionMetadata(String sessionId);

    void saveSessionMetadata(String sessionId, Map<String, Object> metadata);

    boolean isDeviceRegistered(String userId, String device);

    void registerDevice(String userId, String device);

    void recordRequest(String userId, long currentTimeMs);

    int getRecentRequestCount(String userId, long windowStartMs, long currentTimeMs);

    boolean isUserRegistered(String userId);

    void registerUser(String userId);

    boolean isMfaVerified(String userId);

    void markMfaVerified(String userId);

    Map<Object, Object> getHcadAnalysis(String userId);

    void saveHcadAnalysis(String userId, Map<String, Object> analysisData);
}
