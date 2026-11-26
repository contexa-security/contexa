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
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.OAuth2AuthenticationSupport;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;

import java.util.Objects;

/**
 * The user and the session a request belongs to, read from its authentication and the HTTP request without creating a
 * session; no request attribute of the client names either. The user is the one Contexa decides for
 * ({@link ContexaIdentity#userId}: the identity the bridge resolved for the request, else the application's signed-in
 * user, else the user the bridge resolved for Contexa alone). The session is, in this order:
 * <ol>
 *   <li>an agent's or a client's own token request: the agent's session ({@link AgentSessionKey}, A1-11);</li>
 *   <li>a person's token request: the login its token carries (claim sid, kept by a refreshed token);</li>
 *   <li>the sign-in the request's identity names (bridge v2, {@link ContexaIdentity#sessionKey}): for an application
 *       without sessions, the login its own token stands for;</li>
 *   <li>the HTTP session;</li>
 *   <li>the session id the request asked for.</li>
 * </ol>
 */
public final class RequestIdentity {

    private RequestIdentity() {
    }

    /** The user Contexa decides the request for ({@link ContexaIdentity#userId}); null when the request names nobody. */
    @Nullable
    public static String userId(HttpServletRequest request) {
        return request != null ? ContexaIdentity.userId(request) : null;
    }

    @Nullable
    public static String sessionId(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String signIn = signInSession(request, SecurityContextHolder.getContext().getAuthentication());
        if (signIn != null) {
            return signIn;
        }
        HttpSession session = request.getSession(false);
        if (session != null && StringUtils.hasText(session.getId())) {
            return session.getId().trim();
        }
        String requestedSessionId = request.getRequestedSessionId();
        return StringUtils.hasText(requestedSessionId) ? requestedSessionId.trim() : null;
    }

    /**
     * The session a request's sign-in names ahead of its servlet session: an agent's session, a token's login, the
     * session key of the request's identity; null when none names one. It reads the request's attributes and the given
     * authentication only, never the security context, so the code that loads the context gives the authentication it
     * loaded ({@link SessionFingerprintUtil}).
     */
    @Nullable
    static String signInSession(HttpServletRequest request, @Nullable Authentication authentication) {
        String agentSession = AgentSessionKey.of(authentication);
        if (agentSession != null) {
            return agentSession;
        }
        String tokenSession = OAuth2AuthenticationSupport.tokenAttribute(
                authentication, OAuth2AuthenticationSupport.SESSION_ID_CLAIM);
        if (tokenSession != null) {
            return tokenSession;
        }
        return identitySessionKey(request, authentication);
    }

    /**
     * The session key of the request's identity when the identity is the one of the given authentication: read from that
     * very authentication, or, when no user is signed in to it, named by the application itself (its resolver or the
     * request attribute). An identity resolved earlier in the request for another authentication, such as the one met
     * before a sign-in that has not been read again yet, names no session of this one.
     */
    @Nullable
    private static String identitySessionKey(HttpServletRequest request, @Nullable Authentication authentication) {
        String sessionKey = ContexaIdentity.sessionKey(request);
        if (sessionKey == null) {
            return null;
        }
        ContexaIdentity identity = ContexaIdentity.current(request);
        Authentication readFrom = identity != null ? identity.getAuthentication() : null;
        boolean ofThisAuthentication = ContexaIdentity.signedIn(authentication)
                ? Objects.equals(readFrom, authentication)
                : readFrom == null;
        return ofThisAuthentication ? sessionKey : null;
    }
}
