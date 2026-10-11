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

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface SecurityContextDataStore {

    enum EventProcessingClaim {
        ACQUIRED,
        IN_FLIGHT,
        PROCESSED
    }

    record EventProcessingLease(EventProcessingClaim claim, String ownerToken) {
        public EventProcessingLease {
            if (claim == null) {
                throw new IllegalArgumentException("claim is required");
            }
            if (claim == EventProcessingClaim.ACQUIRED
                    && (ownerToken == null || ownerToken.isBlank())) {
                throw new IllegalArgumentException("ownerToken is required for an acquired claim");
            }
        }
    }

    void addSessionAction(String sessionId, String action);

    List<String> getRecentSessionActions(String sessionId, int count);

    /** Adds one decision of the session (an encoded {@link SessionDecisionRecord}), oldest first. */
    default void addSessionDecision(String sessionId, String decisionRecord) {
    }

    /** The session's most recent decisions, oldest first; null when the store keeps no decision history. */
    default List<String> getRecentSessionDecisions(String sessionId, int count) {
        return null;
    }

    /**
     * Carries a session's records to its new id when the servlet container replaces the id of the same session, as
     * session fixation protection does at sign-in and at a step-up MFA. The old id's records go before anything the
     * new id already holds; the old id keeps none.
     */
    default void moveSessionRecords(String fromSessionId, String toSessionId) {
    }

    /**
     * The ids the session had before its id was replaced, newest first (P2 correction 5). Records written under an
     * old id (past records, work profile observations) still belong to the session; empty when the store keeps none.
     */
    default List<String> getSessionPreviousIds(String sessionId) {
        return List.of();
    }

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

    /** Reads stored scope without extending its lifetime. Custom stores must opt in. */
    default String peekAuthorizationScopeState(String tenantId, String userId) {
        throw new UnsupportedOperationException("Non-touching authorization scope read is not supported");
    }

    void setLastRequestTime(String userId, long timestamp);

    Long getLastRequestTime(String userId);

    void setPreviousPath(String userId, String path);

    String getPreviousPath(String userId);

    void recordLoginFailure(String userId, String clientIp, long currentTimeMs);

    int getRecentLoginFailureCount(String userId, String clientIp, long windowStartMs, long currentTimeMs);

    /**
     * The user's own failed sign-ins in the window: failures of other users from the same address are not counted.
     * Null when the user is unknown or the store cannot tell.
     */
    default Integer findRecentLoginFailures(String userId, long windowStartMs, long currentTimeMs) {
        if (userId == null || userId.isBlank()) {
            return null;
        }
        return getRecentLoginFailureCount(userId, null, windowStartMs, currentTimeMs);
    }

    boolean isMfaVerified(String userId);

    void markMfaVerified(String userId);

    /**
     * Marks the user's MFA with the time it was completed on the request clock (null: now). The mark itself lasts its
     * own time on the server clock.
     */
    default void markMfaVerified(String userId, Instant verifiedAt) {
        markMfaVerified(userId);
    }

    /**
     * When the user last completed MFA in any session, while the mark lasts; null when unknown. It is a fact of the
     * user, not of the session a request belongs to.
     */
    default Instant getLastMfaVerifiedAt(String userId) {
        return null;
    }

    /**
     * Removes every per-user record of a user whose account is deleted, in all tenants: work-profile, permission
     * change and authorization scope observations, request tracking, MFA verification, login failures by user and
     * the tracked sessions. Shared records (role scopes, sessions, events) are kept. Stores that cannot delete must
     * fail loudly rather than keep the records silently.
     */
    default void deleteUserData(String userId) {
        throw new UnsupportedOperationException(
                "User context deletion is not supported by " + getClass().getSimpleName());
    }

    EventProcessingClaim claimEventProcessing(String eventId);

    default EventProcessingLease claimEventProcessingLease(String eventId) {
        EventProcessingClaim claim = claimEventProcessing(eventId);
        return new EventProcessingLease(
                claim,
                claim == EventProcessingClaim.ACQUIRED ? UUID.randomUUID().toString() : null);
    }

    default boolean isEventProcessingOwner(String eventId, String ownerToken) {
        return ownerToken != null && !ownerToken.isBlank();
    }

    void markEventProcessed(String eventId);

    default boolean markEventProcessed(String eventId, String ownerToken) {
        if (!isEventProcessingOwner(eventId, ownerToken)) {
            return false;
        }
        markEventProcessed(eventId);
        return true;
    }

    void releaseEventProcessing(String eventId);

    default boolean releaseEventProcessing(String eventId, String ownerToken) {
        if (!isEventProcessingOwner(eventId, ownerToken)) {
            return false;
        }
        releaseEventProcessing(eventId);
        return true;
    }

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
