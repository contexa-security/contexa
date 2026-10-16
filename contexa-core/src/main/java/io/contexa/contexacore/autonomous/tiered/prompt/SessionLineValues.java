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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;

import java.time.Instant;
import java.time.ZoneId;
import java.util.List;

/**
 * The SESSION values a v20 prompt draws from sources the sealed canonical context keeps, and the session's request
 * paths: the same functions the render uses, for the prompt inspector to compare the drawn lines with the sealed
 * sources (R1b-2). The recent denials and the login method's head wait for their renderer defects (P3 extra 13 and 34).
 */
public final class SessionLineValues {

    private SessionLineValues() {
    }

    /** {@code 42 min since login}. */
    public static String sessionAge(int minutes, String basis) {
        return SecurityDecisionPromptValues.sessionAge(minutes, basis);
    }

    /** {@code at 14:23 (1 min before this request)} on the event clock; no distance without the request time. */
    public static String challengeVerified(Instant verified, Instant at, ZoneId zone) {
        return SecurityDecisionPromptValues.challengeVerified(verified, at, zone);
    }

    /** {@code 2 so far: 07:05 (10 min before this request) READ this target -> ALLOW; ...} in the request list order. */
    public static String requestsInSession(List<SessionDecisionRecord> decisions, String currentTarget, Instant at,
                                           ZoneId zone) {
        return SecurityDecisionPromptValues.requestsInSession(decisions, currentTarget, at, zone);
    }

    /** The request's target as the baseline view names it, or null. */
    public static String currentTarget(CanonicalSecurityContext.Resource resource) {
        return SecurityDecisionPromptValues.currentTarget(resource);
    }

    /** The paths of the session's requests in the request list order, or null. */
    public static String sessionPaths(CanonicalSecurityContext.SessionNarrativeProfile narrative) {
        return SecurityDecisionPromptValues.sessionPaths(narrative);
    }

    /** {@code MFA completed in another session 2 h before this request}; null without both times. */
    public static String mfaElsewhere(Instant elsewhere, Instant at) {
        return SecurityDecisionPromptValues.mfaElsewhere(elsewhere, at);
    }

    /** {@code 3 in last 5 min}, or the count with the window not stated; null without a count. */
    public static String failedLogins(CanonicalSecurityContext.Session session) {
        return SecurityDecisionPromptValues.failedLogins(session);
    }

    /** {@code 2 recent MFA failures (window not stated)}, or null. */
    public static String mfaFailures(CanonicalSecurityContext.Session session) {
        return SecurityDecisionPromptValues.mfaFailures(session);
    }

    /** {@code 17 recent requests}, or null. */
    public static String recentRequests(CanonicalSecurityContext.Session session,
                                        CanonicalSecurityContext.SessionNarrativeProfile narrative) {
        return SecurityDecisionPromptValues.recentRequests(session, narrative);
    }

    /** {@code 2 concurrent sessions}, or null. */
    public static String concurrentSessions(CanonicalSecurityContext.Session session) {
        return SecurityDecisionPromptValues.concurrentSessions(session);
    }

    /** {@code 90 days since the password changed}, or null. */
    public static String passwordAge(CanonicalSecurityContext.Session session) {
        return SecurityDecisionPromptValues.passwordAge(session);
    }

    /** {@code 4 recent sensitive accesses}, or null. */
    public static String recentSensitiveAccess(CanonicalSecurityContext.ObservedScope scope) {
        return SecurityDecisionPromptValues.recentSensitiveAccess(scope);
    }

    /** {@code 2 denied in this session (09:00 GET /a; 09:05 /b)} with the host's count; null without either. */
    public static String recentDenied(List<SessionDecisionRecord> decisions,
                                      CanonicalSecurityContext.ObservedScope scope, ZoneId zone) {
        return SecurityDecisionPromptValues.recentDenied(decisions, scope, zone);
    }

    /** {@code PASSWORD (TOKEN) (assurance HIGH)}: the head of the login method line. */
    public static String loginMethodHead(String method, String typed, String assurance) {
        return SecurityDecisionPromptValues.loginMethodHead(method, typed, assurance);
    }

    /** {@code MFA verified} or {@code MFA not verified}; null when the session does not say. */
    public static String mfaState(Boolean verified) {
        return SecurityDecisionPromptValues.mfaState(verified);
    }
}
