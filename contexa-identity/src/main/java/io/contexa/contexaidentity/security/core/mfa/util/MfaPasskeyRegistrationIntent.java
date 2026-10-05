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
 * Records that a user without a passkey asked to register one once the MFA flow completes.
 *
 * <p>A session with an incomplete MFA must not reach the passkey registration endpoints, otherwise
 * the first factor alone would be enough to enroll an attacker-controlled passkey. A user who has no
 * passkey yet therefore completes the MFA flow with the email one-time token factor first. When the
 * user asks for that on the MFA passkey page, the factor selection records the intent here, bound to
 * the MFA session that was active at that time. The final MFA success consumes the intent once and
 * sends the user to the passkey registration page instead of the regular target, which is kept as
 * the return URL so that the registration page can lead the user back to it.</p>
 *
 * <p>Both attribute names start with {@code SPRING_SECURITY_} so that session fixation strategies
 * which migrate only Spring Security attributes keep them together with the SecurityContext. An
 * intent recorded for a previous MFA session is never honored.</p>
 */
public final class MfaPasskeyRegistrationIntent {

    public static final String SESSION_ATTRIBUTE = "SPRING_SECURITY_CONTEXA_MFA_PASSKEY_REGISTRATION_INTENT";

    public static final String RETURN_URL_SESSION_ATTRIBUTE = "SPRING_SECURITY_CONTEXA_PASSKEY_REGISTRATION_RETURN_URL";

    /**
     * Request parameter (or JSON body field) of the MFA factor selection request that asks to
     * register a passkey after the MFA flow completes.
     */
    public static final String REQUEST_PARAMETER = "registerPasskeyAfterMfa";

    private MfaPasskeyRegistrationIntent() {
    }

    /**
     * Records the intent for the given MFA session, creating the HTTP session if needed.
     */
    public static void record(HttpServletRequest request, String mfaSessionId) {
        if (!StringUtils.hasText(mfaSessionId)) {
            return;
        }
        request.getSession(true).setAttribute(SESSION_ATTRIBUTE, mfaSessionId);
    }

    /**
     * Removes the recorded intent and returns whether it had been recorded for the given MFA session.
     * An intent of another MFA session is removed as well, but reported as absent.
     */
    public static boolean consume(HttpServletRequest request, @Nullable String mfaSessionId) {
        Object recorded = removeAttribute(request, SESSION_ATTRIBUTE);
        return recorded != null
                && StringUtils.hasText(mfaSessionId)
                && mfaSessionId.equals(recorded.toString());
    }

    /**
     * Stores the URL the user would have been sent to after the MFA flow, so that the passkey
     * registration page can lead back to it. Only same-origin paths are stored.
     */
    public static void storeReturnUrl(HttpServletRequest request, @Nullable String returnUrl) {
        if (!isSameOriginPath(returnUrl)) {
            removeAttribute(request, RETURN_URL_SESSION_ATTRIBUTE);
            return;
        }
        request.getSession(true).setAttribute(RETURN_URL_SESSION_ATTRIBUTE, returnUrl);
    }

    /**
     * Returns the stored return URL, or {@code null} when none is stored.
     */
    @Nullable
    public static String getReturnUrl(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object value;
        try {
            value = session.getAttribute(RETURN_URL_SESSION_ATTRIBUTE);
        } catch (IllegalStateException e) {
            return null;
        }
        String returnUrl = value != null ? value.toString() : null;
        return isSameOriginPath(returnUrl) ? returnUrl : null;
    }

    /**
     * Removes the stored return URL, if any.
     */
    public static void clearReturnUrl(HttpServletRequest request) {
        removeAttribute(request, RETURN_URL_SESSION_ATTRIBUTE);
    }

    private static boolean isSameOriginPath(@Nullable String url) {
        return StringUtils.hasText(url)
                && url.startsWith("/")
                && !url.startsWith("//")
                && !url.contains("\\");
    }

    @Nullable
    private static Object removeAttribute(HttpServletRequest request, String name) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        try {
            Object value = session.getAttribute(name);
            session.removeAttribute(name);
            return value;
        } catch (IllegalStateException e) {
            // The session has already been invalidated, so the attribute is gone with it.
            return null;
        }
    }
}
