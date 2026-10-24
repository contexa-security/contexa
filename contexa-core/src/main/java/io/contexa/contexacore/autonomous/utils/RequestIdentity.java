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

import io.contexa.contexacommon.security.bridge.AgentSessionKey;
import io.contexa.contexacommon.security.bridge.OAuth2AuthenticationSupport;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;

/**
 * The user and the session a request belongs to, read from its authentication and the HTTP request without creating a
 * session. No request attribute names them: the user is the authenticated principal, and the session is the login a
 * token carries (claim sid), else the HTTP session, else the session id the request asked for. An agent's or a
 * client's own token request has the agent's session instead ({@link AgentSessionKey}, A1-11).
 */
public final class RequestIdentity {

    private RequestIdentity() {
    }

    public static String userId(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && StringUtils.hasText(authentication.getName())) {
            return authentication.getName().trim();
        }
        return null;
    }

    public static String sessionId(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // An agent's token request is grouped within that agent, never with the person it acts for (A1-11).
        String agentSession = AgentSessionKey.of(authentication);
        if (agentSession != null) {
            return agentSession;
        }
        // A token (OAuth2) request is identified by the login its token carries (claim sid, kept by a refreshed
        // token), whether or not the request also holds an HTTP session.
        String tokenSession = OAuth2AuthenticationSupport.tokenAttribute(
                authentication, OAuth2AuthenticationSupport.SESSION_ID_CLAIM);
        if (tokenSession != null) {
            return tokenSession;
        }
        HttpSession session = request.getSession(false);
        if (session != null && StringUtils.hasText(session.getId())) {
            return session.getId().trim();
        }
        String requestedSessionId = request.getRequestedSessionId();
        return StringUtils.hasText(requestedSessionId) ? requestedSessionId.trim() : null;
    }
}
