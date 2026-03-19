package io.contexa.contexacore.autonomous.store;

import java.util.List;

public interface SecurityContextDataStore {

    void addSessionAction(String sessionId, String action);

    List<String> getRecentSessionActions(String sessionId, int count);

    void setSessionRisk(String sessionId, double riskScore);

    void setLastRequestTime(String userId, long timestamp);

    Long getLastRequestTime(String userId);

    void setPreviousPath(String userId, String path);

    String getPreviousPath(String userId);

    boolean tryMarkEventAsProcessed(String eventId);

    void storeSoarExecution(String eventId, Object data);

    void trackUserSession(String userId, String sessionId);
}
