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
package io.contexa.contexaidentity.security.core.mfa.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

/**
 * Marks an HTTP session whose primary authentication succeeded but whose MFA has not completed yet.
 *
 * <p>The primary MFA authentication filters persist the authenticated SecurityContext into the
 * HTTP session so that the authentication survives the redirects of the MFA flow. This marker is
 * stored next to that SecurityContext and lets the MFA pending access control restrict the session
 * to MFA progress requests until the flow reaches a final success.</p>
 *
 * <p>The marker is set before the SecurityContext is saved, removed only when the MFA flow completes
 * (or MFA is not required), and disappears together with the session on logout or invalidation.
 * Failure, cancellation and expiry keep the marker, so the session stays restricted until a new
 * login. The attribute name starts with {@code SPRING_SECURITY_} so that session fixation strategies
 * which migrate only Spring Security attributes keep it together with the SecurityContext.</p>
 */
public final class MfaPendingSessionMarker {

    public static final String SESSION_ATTRIBUTE = "SPRING_SECURITY_CONTEXA_MFA_PENDING_FLOW";

    private MfaPendingSessionMarker() {
    }

    /**
     * Marks the current session as MFA pending for the given flow, creating the session if needed.
     */
    public static void mark(HttpServletRequest request, @Nullable String flowTypeName) {
        String value = StringUtils.hasText(flowTypeName) ? flowTypeName : MfaFlowTypeUtils.getBaseMfaTypeName();
        request.getSession(true).setAttribute(SESSION_ATTRIBUTE, value);
    }

    /**
     * Removes the MFA pending marker from the current session, if any.
     */
    public static void clear(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }
        try {
            session.removeAttribute(SESSION_ATTRIBUTE);
        } catch (IllegalStateException ignored) {
            // The session has already been invalidated, so the marker is gone with it.
        }
    }

    /**
     * Returns the MFA flow type name the current session is pending on, or {@code null} when the
     * session is not marked.
     */
    @Nullable
    public static String getPendingFlowTypeName(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object value;
        try {
            value = session.getAttribute(SESSION_ATTRIBUTE);
        } catch (IllegalStateException e) {
            return null;
        }
        if (value == null) {
            return null;
        }
        String flowTypeName = value.toString();
        return StringUtils.hasText(flowTypeName) ? flowTypeName : MfaFlowTypeUtils.getBaseMfaTypeName();
    }
}
