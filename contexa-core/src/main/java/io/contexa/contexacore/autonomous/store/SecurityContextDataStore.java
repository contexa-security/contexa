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
package io.contexa.contexacore.autonomous.store;

import java.util.List;

public interface SecurityContextDataStore {

    enum EventProcessingClaim {
        ACQUIRED,
        IN_FLIGHT,
        PROCESSED
    }

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

    void recordLoginFailure(String userId, String clientIp, long currentTimeMs);

    int getRecentLoginFailureCount(String userId, String clientIp, long windowStartMs, long currentTimeMs);

    boolean isMfaVerified(String userId);

    void markMfaVerified(String userId);

    EventProcessingClaim claimEventProcessing(String eventId);

    void markEventProcessed(String eventId);

    void releaseEventProcessing(String eventId);

    default boolean tryMarkEventAsProcessed(String eventId) {
        EventProcessingClaim claim = claimEventProcessing(eventId);
        if (claim != EventProcessingClaim.ACQUIRED) {
            return false;
        }
        markEventProcessed(eventId);
        return true;
    }

    void storeSoarExecution(String eventId, Object data);

    void trackUserSession(String userId, String sessionId);
}
