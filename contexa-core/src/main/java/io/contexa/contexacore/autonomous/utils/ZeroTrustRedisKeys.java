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

import java.util.Locale;

public class ZeroTrustRedisKeys {

    private static final String NAMESPACE = "security";

    /** A value written into a SCAN or KEYS pattern as itself: the glob characters escaped. */
    public static String globLiteral(String value) {
        StringBuilder escaped = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            if (c == '\\' || c == '*' || c == '?' || c == '[' || c == ']') {
                escaped.append('\\');
            }
            escaped.append(c);
        }
        return escaped.toString();
    }

    public static String threatScore(String userId) {
        validateUserId(userId);
        return String.format("threat_score:%s", userId);
    }

    public static String userSessions(String userId) {
        validateUserId(userId);
        return String.format("%s:user:sessions:%s", NAMESPACE, userId);
    }

    /**
     * QF-57: the user's tracked session ids that die at a known time, each scored by that time (epoch milliseconds);
     * the key expires with the last of them.
     */
    public static String userSessionDeadlines(String userId) {
        validateUserId(userId);
        return String.format("%s:user:session-deadlines:%s", NAMESPACE, userId);
    }

    /**
     * QF-57: the user's tracked session ids nothing bounds the life of, each scored by its last registration (epoch
     * milliseconds); at most the per-user limit are kept.
     */
    public static String userUntimedSessions(String userId) {
        validateUserId(userId);
        return String.format("%s:user:session-untimed:%s", NAMESPACE, userId);
    }

    public static String userDevices(String userId) {
        validateUserId(userId);
        return String.format("%s:user:devices:%s", NAMESPACE, userId);
    }

    public static String userRegistered(String userId) {
        validateUserId(userId);
        return String.format("%s:user:registered:%s", NAMESPACE, userId);
    }

    public static String autonomousActionAnalysis(String userId) {
        validateUserId(userId);
        return String.format("%s:autonomous:action:analysis:%s", NAMESPACE, ZeroTrustUserKey.of(userId));
    }

    public static String autonomousLastVerifiedAction(String userId) {
        validateUserId(userId);
        return String.format("%s:autonomous:action:last-verified:%s", NAMESPACE, ZeroTrustUserKey.of(userId));
    }

    public static String autonomousLastVerifiedActionContext(String userId) {
        validateUserId(userId);
        return String.format("%s:autonomous:action:last-verified-context:%s", NAMESPACE, ZeroTrustUserKey.of(userId));
    }

    /** Q-12: the contexts that answered the CHALLENGE still held for the user's other sessions. */
    public static String autonomousChallengeHold(String userId) {
        validateUserId(userId);
        return String.format("%s:autonomous:action:challenge-hold:%s", NAMESPACE, ZeroTrustUserKey.of(userId));
    }

    public static String autonomousDecisionAuditPending(String userId) {
        validateUserId(userId);
        return String.format("%s:autonomous:action:audit-pending:%s", NAMESPACE, ZeroTrustUserKey.of(userId));
    }

    public static String userBlocked(String userId) {
        validateUserId(userId);
        return userBlockedAsTyped(ZeroTrustUserKey.of(userId));
    }

    /**
     * The BLOCK flag under the name as it was given, where a version before Q-18 stored it. A BLOCK has no TTL, so such a
     * flag is read and removed beside {@link #userBlocked} and never lapses with an upgrade.
     */
    public static String userBlockedAsTyped(String userId) {
        validateUserId(userId);
        return String.format("security:blocked:users:%s", userId);
    }

    public static String escalateRetry(String userId) {
        validateUserId(userId);
        return "security:escalate:retry:" + ZeroTrustUserKey.of(userId);
    }

    public static String blockMfaPending(String userId) {
        validateUserId(userId);
        return String.format("%s:block:mfa:pending:%s", NAMESPACE, ZeroTrustUserKey.of(userId));
    }

    public static String blockMfaVerified(String userId) {
        validateUserId(userId);
        return String.format("%s:block:mfa:verified:%s", NAMESPACE, ZeroTrustUserKey.of(userId));
    }

    public static String blockMfaFailCount(String userId) {
        validateUserId(userId);
        return String.format("%s:block:mfa:failCount:%s", NAMESPACE, ZeroTrustUserKey.of(userId));
    }

    /** Q-14: the version of what accounts may do, one for all accounts. */
    public static String authoritiesVersion() {
        return String.format("%s:context:authorities:version", NAMESPACE);
    }

    public static String authenticationMfaVerified(String userId) {
        validateUserId(userId);
        return String.format("%s:context:authentication:mfa:verified:%s", NAMESPACE, userId);
    }

    /** Q-16: the contexts the user passed a step-up in, each with when that ends and when it was passed. */
    public static String authenticationChallengeVerified(String userId) {
        validateUserId(userId);
        return String.format("%s:context:authentication:challenge:verified:%s", NAMESPACE, userId);
    }

    public static String authenticationLoginFailuresByUser(String userId) {
        validateUserId(userId);
        return String.format("%s:context:authentication:failure:user:%s", NAMESPACE, userId);
    }

    /** The keys of failed sign-ins, ordered by their last failure, so that their number keeps within its bound. */
    public static String authenticationLoginFailureKeys() {
        return String.format("%s:context:authentication:failures:keys", NAMESPACE);
    }

    /** Held while a name without a record of failures may have lost it to that bound. */
    public static String authenticationLoginFailuresLost() {
        return String.format("%s:context:authentication:failures:lost", NAMESPACE);
    }

    public static String authenticationLoginFailuresByIp(String clientIp) {
        if (clientIp == null || clientIp.trim().isEmpty()) {
            throw new IllegalArgumentException("Client IP cannot be null or empty");
        }
        return String.format("%s:context:authentication:failure:ip:%s", NAMESPACE, clientIp);
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

    public static String sessionDecisions(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:decisions:%s", NAMESPACE, sessionId);
    }

    /** The ids a session had before the servlet container replaced its id, newest first (P2 correction 5). */
    public static String sessionPreviousIds(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:previous-ids:%s", NAMESPACE, sessionId);
    }

    public static String sessionFirstClient(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:first-client:%s", NAMESPACE, sessionId);
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

    /** The facts of the user's requests a restriction stopped, kept to be learned after verification (W5-2). */
    public static String verificationLearning(String userId) {
        validateUserId(userId);
        return String.format("%s:context:user:verification-learning:%s", NAMESPACE, userId);
    }

    /** How the verification of an event's stopped request ended, for its record stored after it (W5-4). */
    public static String verificationOutcome(String eventId) {
        if (eventId == null || eventId.trim().isEmpty()) {
            throw new IllegalArgumentException("Event ID cannot be null or empty");
        }
        return String.format("%s:context:event:verification-outcome:%s", NAMESPACE, eventId);
    }

    /** When the user's account was deleted, while its late writes are told apart from a later account's (Q-15). */
    public static String accountDeletion(String userId) {
        validateUserId(userId);
        return String.format("%s:context:user:account-deletion:%s", NAMESPACE, userId);
    }

    /** The user's allowed requests whose first-seen values wait for promotion (W5-1). */
    public static String promotionLearning(String userId) {
        validateUserId(userId);
        return String.format("%s:context:user:promotion-learning:%s", NAMESPACE, userId);
    }

    /** The requests a filter stopped under the user's challenge, by method and URI, until the step-up (N-LRN-3). */
    public static String stoppedRequests(String userId) {
        validateUserId(userId);
        return String.format("%s:context:user:stopped-requests:%s", NAMESPACE, userId);
    }

    public static String userLastRequestTime(String userId) {
        validateUserId(userId);
        return String.format("%s:context:user:last-request:%s", NAMESPACE, userId);
    }

    public static String userPreviousPath(String userId) {
        validateUserId(userId);
        return String.format("%s:context:user:previous-path:%s", NAMESPACE, userId);
    }

    public static String approvalWorkflow(Long proposalId) {
        if (proposalId == null) {
            throw new IllegalArgumentException("Proposal ID cannot be null");
        }
        return String.format(Locale.ROOT, "%s:governance:approval:workflow:%d", NAMESPACE, proposalId);
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

