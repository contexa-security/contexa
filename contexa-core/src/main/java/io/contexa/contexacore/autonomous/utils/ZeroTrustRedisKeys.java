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
package io.contexa.contexacore.autonomous.utils;

public class ZeroTrustRedisKeys {

    private static final String NAMESPACE = "security";

    public static String threatScore(String userId) {
        validateUserId(userId);
        return String.format("threat_score:%s", userId);
    }

    public static String userSessions(String userId) {
        validateUserId(userId);
        return String.format("%s:user:sessions:%s", NAMESPACE, userId);
    }

    public static String userDevices(String userId) {
        validateUserId(userId);
        return String.format("%s:user:devices:%s", NAMESPACE, userId);
    }

    public static String userRegistered(String userId) {
        validateUserId(userId);
        return String.format("%s:user:registered:%s", NAMESPACE, userId);
    }

    public static String hcadAnalysis(String userId) {
        validateUserId(userId);
        return String.format("%s:hcad:analysis:%s", NAMESPACE, userId);
    }

    public static String hcadLastVerifiedAction(String userId) {
        validateUserId(userId);
        return String.format("%s:hcad:lastAction:%s", NAMESPACE, userId);
    }

    public static String hcadLastVerifiedActionContext(String userId) {
        validateUserId(userId);
        return String.format("%s:hcad:lastActionContext:%s", NAMESPACE, userId);
    }

    public static String userBlocked(String userId) {
        validateUserId(userId);
        return String.format("security:blocked:users:%s", userId);
    }

    public static String blockMfaPending(String userId) {
        validateUserId(userId);
        return String.format("%s:block:mfa:pending:%s", NAMESPACE, userId);
    }

    public static String blockMfaVerified(String userId) {
        validateUserId(userId);
        return String.format("%s:block:mfa:verified:%s", NAMESPACE, userId);
    }

    public static String blockMfaFailCount(String userId) {
        validateUserId(userId);
        return String.format("%s:block:mfa:failCount:%s", NAMESPACE, userId);
    }

    /**
     * MFA verified key for HCAD/CHALLENGE flow.
     * Intentionally distinct from {@link #blockMfaVerified(String)} which is reserved
     * for the BLOCK MFA recovery flow. CHALLENGE MFA writes to this key so the LLM
     * prompt can read MfaVerified independently of BLOCK state.
     * Prefix is kept without NAMESPACE for backward compatibility with existing data.
     */
    public static String hcadMfaVerified(String userId) {
        validateUserId(userId);
        return "security:mfa:verified:" + userId;
    }

    /**
     * Per-user request counter ZSet key (5-minute sliding window) used by HCAD.
     * Prefix is kept without NAMESPACE for backward compatibility with existing data.
     */
    public static String userRequestCounter(String userId) {
        validateUserId(userId);
        return "hcad:request:counter:" + userId;
    }

    public static String hcadLoginFailuresByUser(String userId) {
        validateUserId(userId);
        return "hcad:login:failure:user:" + userId;
    }

    public static String hcadLoginFailuresByIp(String clientIp) {
        if (clientIp == null || clientIp.trim().isEmpty()) {
            throw new IllegalArgumentException("Client IP cannot be null or empty");
        }
        return "hcad:login:failure:ip:" + clientIp;
    }

    public static String soarExecution(String eventId) {
        if (eventId == null || eventId.trim().isEmpty()) {
            throw new IllegalArgumentException("Event ID cannot be null or empty");
        }
        return String.format("%s:soar:execution:%s", NAMESPACE, eventId);
    }

    public static String sessionMetadata(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:meta:%s", NAMESPACE, sessionId);
    }

    public static String invalidSession(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:invalid:%s", NAMESPACE, sessionId);
    }

    public static String sessionActions(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:actions:%s", NAMESPACE, sessionId);
    }

    public static String sessionNarrativeActions(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:narrative:actions:%s", NAMESPACE, sessionId);
    }

    public static String sessionProtectableAccesses(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:narrative:protectable:%s", NAMESPACE, sessionId);
    }

    public static String sessionRequestIntervals(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:narrative:intervals:%s", NAMESPACE, sessionId);
    }

    public static String sessionStartedAt(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:narrative:startedAt:%s", NAMESPACE, sessionId);
    }

    public static String sessionLastRequestTime(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:narrative:lastRequest:%s", NAMESPACE, sessionId);
    }

    public static String sessionPreviousPath(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:narrative:previousPath:%s", NAMESPACE, sessionId);
    }

    public static String sessionRisk(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:risk:%s", NAMESPACE, sessionId);
    }

    public static String userWorkProfileObservations(String scopeKey) {
        validateScopeKey(scopeKey);
        return String.format("%s:work-profile:observations:%s", NAMESPACE, scopeKey);
    }

    public static String roleScopeObservations(String scopeKey) {
        validateScopeKey(scopeKey);
        return String.format("%s:role-scope:observations:%s", NAMESPACE, scopeKey);
    }

    public static String userPermissionChangeObservations(String scopeKey) {
        validateScopeKey(scopeKey);
        return String.format("%s:role-scope:permission-changes:%s", NAMESPACE, scopeKey);
    }

    public static String userAuthorizationScopeState(String scopeKey) {
        validateScopeKey(scopeKey);
        return String.format("%s:role-scope:authorization-state:%s", NAMESPACE, scopeKey);
    }

    public static String userLastRequestTime(String userId) {
        validateUserId(userId);
        return String.format("%s:hcad:last:request:%s", NAMESPACE, userId);
    }

    public static String userPreviousPath(String userId) {
        validateUserId(userId);
        return String.format("%s:hcad:previous:path:%s", NAMESPACE, userId);
    }

    public static String approvalWorkflow(Long proposalId) {
        if (proposalId == null) {
            throw new IllegalArgumentException("Proposal ID cannot be null");
        }
        return String.format("%s:governance:approval:workflow:%d", NAMESPACE, proposalId);
    }

    public static String approvalWorkflowIndex() {
        return String.format("%s:governance:approval:index", NAMESPACE);
    }

    public static String approvalRequest(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            throw new IllegalArgumentException("Request ID cannot be null or empty");
        }
        return String.format("%s:governance:approval:request:%s", NAMESPACE, requestId);
    }

    public static String eventProcessed(String eventId) {
        if (eventId == null || eventId.isBlank()) {
            throw new IllegalArgumentException("Event ID cannot be null or empty");
        }
        return String.format("%s:processed:%s", NAMESPACE, eventId);
    }

    public static String eventProcessing(String eventId) {
        if (eventId == null || eventId.isBlank()) {
            throw new IllegalArgumentException("Event ID cannot be null or empty");
        }
        return String.format("%s:processing:%s", NAMESPACE, eventId);
    }

    public static String analysisTriggerInflight(String dedupKey) {
        validateTriggerKey(dedupKey);
        return String.format("%s:hcad:pretrigger:inflight:%s", NAMESPACE, dedupKey);
    }

    public static String analysisTriggerCooldown(String dedupKey) {
        validateTriggerKey(dedupKey);
        return String.format("%s:hcad:pretrigger:cooldown:%s", NAMESPACE, dedupKey);
    }

    public static String analysisTriggerNegative(String baseKey) {
        validateTriggerKey(baseKey);
        return String.format("%s:hcad:pretrigger:negative:%s", NAMESPACE, baseKey);
    }

    public static String analysisTriggerRateLimit(String rateKey) {
        validateTriggerKey(rateKey);
        return String.format("%s:hcad:pretrigger:rate:%s", NAMESPACE, rateKey);
    }

    public static String analysisTriggerEvaluation(String stateKey) {
        validateTriggerKey(stateKey);
        return String.format("%s:hcad:pretrigger:evaluation:%s", NAMESPACE, stateKey);
    }

    public static String hcadObservationWindow(String actorSessionKey) {
        validateTriggerKey(actorSessionKey);
        return String.format("%s:hcad:pretrigger:window:%s", NAMESPACE, actorSessionKey);
    }

    public static String hcadObservationWindowObservations(String actorSessionKey, String windowId) {
        validateTriggerKey(actorSessionKey);
        validateTriggerKey(windowId);
        return String.format("%s:hcad:pretrigger:observations:%s:%s", NAMESPACE, actorSessionKey, windowId);
    }

    public static String hcadObservationWindowObservationsPrefix(String actorSessionKey) {
        validateTriggerKey(actorSessionKey);
        return String.format("%s:hcad:pretrigger:observations:%s:", NAMESPACE, actorSessionKey);
    }

    public static String hcadObservationWindowDeepEvaluation(String actorSessionKey, String windowId) {
        validateTriggerKey(actorSessionKey);
        validateTriggerKey(windowId);
        return String.format("%s:hcad:pretrigger:window:evaluated:%s:%s", NAMESPACE, actorSessionKey, windowId);
    }

    public static String hcadObservationWindowAnchorSignatures(String actorSessionKey, String windowId) {
        validateTriggerKey(actorSessionKey);
        validateTriggerKey(windowId);
        return String.format("%s:hcad:pretrigger:window:anchors:%s:%s", NAMESPACE, actorSessionKey, windowId);
    }

    private static void validateTriggerKey(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("Trigger key cannot be null or empty");
        }
    }
    private static void validateUserId(String userId) {
        if (userId == null || userId.trim().isEmpty()) {
            throw new IllegalArgumentException("UserId is required for Zero Trust architecture");
        }
    }

    private static void validateSessionId(String sessionId) {
        if (sessionId == null || sessionId.trim().isEmpty()) {
            throw new IllegalArgumentException("SessionId cannot be null or empty");
        }
    }

    private static void validateScopeKey(String scopeKey) {
        if (scopeKey == null || scopeKey.trim().isEmpty()) {
            throw new IllegalArgumentException("Scope key cannot be null or empty");
        }
    }
}

