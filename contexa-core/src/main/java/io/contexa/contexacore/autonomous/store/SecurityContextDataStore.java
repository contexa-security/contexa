package io.contexa.contexacore.autonomous.store;

import java.util.List;

public interface SecurityContextDataStore {

    // --- Session actions (SecurityDecisionPostProcessor writes, Layer1 reads) ---

    void addSessionAction(String sessionId, String action);

    List<String> getRecentSessionActions(String sessionId, int count);

    void setSessionRisk(String sessionId, double riskScore);

    // --- Activity context (HCADContextExtractor writes, Layer1 reads) ---

    void setLastRequestTime(String userId, long timestamp);

    Long getLastRequestTime(String userId);

    void setPreviousPath(String userId, String path);

    String getPreviousPath(String userId);

    // --- Event deduplication (SecurityPlaneAgent) ---

    boolean tryMarkEventAsProcessed(String eventId);

    // --- SOAR execution (Layer2ExpertStrategy) ---

    void storeSoarExecution(String eventId, Object data);

    // --- User session tracking (AIReactiveSecurityContextRepository) ---

    void trackUserSession(String userId, String sessionId);
}
