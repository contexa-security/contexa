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
package io.contexa.contexacore.security;

import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Keeps an open session in step with its account (Q-14). A session holds what its user could do at sign-in, so a right
 * taken away stayed and a disabled user stayed signed in. A version in the shared store moves on when an administrator
 * changes accounts; a session behind it reads its account again on its next request, once: the new authorities replace
 * the old ones, and an account that is gone or disabled ends the session.
 * <p>
 * Only an account of Contexa is read: a principal of the application's own stays as it is. When the account cannot be
 * read the session goes on as it was and tries again on its next request: a store that fails does not sign anyone out.
 */
@Slf4j
public class SessionAccountRefresher {

    /** Starts with SPRING_SECURITY_ so that session fixation strategies keep it with the security context. */
    static final String VERSION_ATTRIBUTE = "SPRING_SECURITY_CONTEXA_AUTHORITIES_VERSION";

    /** What became of the session. */
    public enum Outcome { CURRENT, REFRESHED, ACCOUNT_ENDED }

    private final SecurityContextDataStore store;
    private final UserDetailsService accounts;

    public SessionAccountRefresher(SecurityContextDataStore store, UserDetailsService accounts) {
        this.store = store;
        this.accounts = accounts;
    }

    /** Records that a session just signed in holds the account as it is now, so its first request reads nothing. */
    public void signedIn(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }
        try {
            if (session.getAttribute(VERSION_ATTRIBUTE) == null) {
                session.setAttribute(VERSION_ATTRIBUTE, store.authoritiesVersion());
            }
        } catch (RuntimeException e) {
            log.error("[SessionAccount] Failed to record the account version of a session", e);
        }
    }

    /**
     * Brings the context of the request's session up to its account.
     *
     * @param contextKey the session attribute the context is kept under, to store a changed context again: a session
     *                   store that serializes its attributes would otherwise lose the change
     */
    public Outcome refresh(SecurityContext context, HttpServletRequest request, String contextKey) {
        Authentication authentication = context.getAuthentication();
        HttpSession session = request.getSession(false);
        if (session == null || authentication == null
                || !(authentication.getPrincipal() instanceof UnifiedCustomUserDetails)) {
            return Outcome.CURRENT;
        }
        try {
            long version = store.authoritiesVersion();
            if (Long.valueOf(version).equals(session.getAttribute(VERSION_ATTRIBUTE))) {
                return Outcome.CURRENT;
            }
            UserDetails account = readAccount(authentication.getName());
            if (!(account instanceof UnifiedCustomUserDetails details) || !details.getAccount().isEnabled()) {
                return Outcome.ACCOUNT_ENDED;
            }
            UsernamePasswordAuthenticationToken refreshed = UsernamePasswordAuthenticationToken.authenticated(
                    details, authentication.getCredentials(), details.getAuthorities());
            refreshed.setDetails(authentication.getDetails());
            context.setAuthentication(refreshed);
            session.setAttribute(VERSION_ATTRIBUTE, version);
            session.setAttribute(contextKey, context);
            return Outcome.REFRESHED;
        } catch (RuntimeException e) {
            log.error("[SessionAccount] The account of a session could not be read; the session goes on as it was: "
                    + "userId={}", authentication.getName(), e);
            return Outcome.CURRENT;
        }
    }

    private UserDetails readAccount(String username) {
        try {
            return accounts.loadUserByUsername(username);
        } catch (UsernameNotFoundException gone) {
            return null;
        }
    }
}
