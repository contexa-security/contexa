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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;

/**
 * Resolves synthetic verification context and normal request identity/session facts
 * from the current HTTP request without forcing new session creation.
 */
public final class OfficialVerificationRequestContext {

    public static final String REQUESTED_USER_ID = "officialVerification.requestedUserId";
    public static final String SYNTHETIC_SESSION_ID = "officialVerification.sessionId";

    private static final String USER_ID_ATTRIBUTE = "contexa.userId";
    private static final String HCAD_USER_ID = "hcad.user_id";
    private static final String HCAD_USER_ID_CAMEL = "hcad.userId";
    private static final String HCAD_SESSION_ID = "hcad.session_id";
    private static final String HCAD_SESSION_ID_CAMEL = "hcad.sessionId";

    private OfficialVerificationRequestContext() {
    }

    public static void apply(HttpServletRequest request, String requestedUserId, String syntheticSessionId) {
        if (request == null) {
            return;
        }
        putIfText(request, REQUESTED_USER_ID, requestedUserId);
        putIfText(request, USER_ID_ATTRIBUTE, requestedUserId);
        putIfText(request, HCAD_USER_ID, requestedUserId);
        putIfText(request, HCAD_USER_ID_CAMEL, requestedUserId);
        putIfText(request, SYNTHETIC_SESSION_ID, syntheticSessionId);
        putIfText(request, HCAD_SESSION_ID, syntheticSessionId);
        putIfText(request, HCAD_SESSION_ID_CAMEL, syntheticSessionId);
    }

    public static String resolveUserId(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        String attributeUserId = firstTextAttribute(
                request,
                REQUESTED_USER_ID,
                USER_ID_ATTRIBUTE,
                HCAD_USER_ID,
                HCAD_USER_ID_CAMEL
        );
        if (StringUtils.hasText(attributeUserId)) {
            return attributeUserId;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && StringUtils.hasText(authentication.getName())) {
            return authentication.getName().trim();
        }
        return null;
    }

    public static String resolveSessionId(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        String override = firstTextAttribute(
                request,
                SYNTHETIC_SESSION_ID,
                HCAD_SESSION_ID,
                HCAD_SESSION_ID_CAMEL
        );
        if (StringUtils.hasText(override)) {
            return override;
        }

        HttpSession session = request.getSession(false);
        if (session != null && StringUtils.hasText(session.getId())) {
            return session.getId().trim();
        }

        String requestedSessionId = request.getRequestedSessionId();
        return StringUtils.hasText(requestedSessionId) ? requestedSessionId.trim() : null;
    }

    private static void putIfText(HttpServletRequest request, String name, String value) {
        if (request != null && StringUtils.hasText(name) && StringUtils.hasText(value)) {
            request.setAttribute(name, value.trim());
        }
    }

    private static String firstTextAttribute(HttpServletRequest request, String... attributeNames) {
        if (request == null || attributeNames == null) {
            return null;
        }
        for (String attributeName : attributeNames) {
            Object value = request.getAttribute(attributeName);
            if (value == null) {
                continue;
            }
            String text = value.toString();
            if (StringUtils.hasText(text)) {
                return text.trim();
            }
        }
        return null;
    }
}