package io.contexa.contexacore.autonomous.store;

import java.util.List;

public interface SecurityContextDataStore {

    void addSessionAction(String sessionId, String action);

    List<String> getRecentSessionActions(String sessionId, int count);

    void addSessionNarrativeActionFamily(String sessionId, String actionFamily);

    List<String> getRecentSessionNarrativeActionFamilies(String sessionId, int count);

    void addSessionProtectableAccess(String sessionId, String resourcePath);

    List<String> getRecentSessionProtectableAccesses(String sessionId, int count);

    void addSessionRequestInterval(String sessionId, long intervalMs);

    List<Long> getRecentSessionRequestIntervals(String sessionId, int count);

    void setSessionStartedAt(String sessionId, long timestamp);

    Long getSessionStartedAt(String sessionId);

    void setSessionLastRequestTime(String sessionId, long timestamp);

    Long getSessionLastRequestTime(String sessionId);

    void setSessionPreviousPath(String sessionId, String path);

    String getSessionPreviousPath(String sessionId);

    void setSessionRisk(String sessionId, double riskScore);

    void addWorkProfileObservation(String tenantId, String userId, String observation);

    List<String> getRecentWorkProfileObservations(String tenantId, String userId, int count);

    void addRoleScopeObservation(String tenantId, String scopeKey, String observation);

    List<String> getRecentRoleScopeObservations(String tenantId, String scopeKey, int count);

    void addPermissionChangeObservation(String tenantId, String userId, String observation);

    List<String> getRecentPermissionChangeObservations(String tenantId, String userId, int count);

    void setAuthorizationScopeState(String tenantId, String userId, String state);

    String getAuthorizationScopeState(String tenantId, String userId);

    void setLastRequestTime(String userId, long timestamp);

    Long getLastRequestTime(String userId);

    void setPreviousPath(String userId, String path);

    String getPreviousPath(String userId);

    boolean tryMarkEventAsProcessed(String eventId);

    void storeSoarExecution(String eventId, Object data);

    void trackUserSession(String userId, String sessionId);
}
