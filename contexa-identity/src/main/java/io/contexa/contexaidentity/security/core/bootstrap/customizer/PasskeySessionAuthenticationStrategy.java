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
package io.contexa.contexaidentity.security.core.bootstrap.customizer;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.util.Assert;

/**
 * The session strategy of a chain as a passkey sign-in needs it. Spring Security's passkey sign-in carries the
 * passkey's user entity as its principal, and that is another object at every sign-in: the registry of sessions could
 * not tell that two of them are one person's, so the limit of sessions never counted a passkey sign-in. The strategy is
 * given the sign-in under the person's entry of the user store, as the other sign-ins of the chain carry it.
 */
@Slf4j
public final class PasskeySessionAuthenticationStrategy implements SessionAuthenticationStrategy {

    private final SessionAuthenticationStrategy delegate;
    private final UserDetailsService users;

    public PasskeySessionAuthenticationStrategy(SessionAuthenticationStrategy delegate, UserDetailsService users) {
        Assert.notNull(delegate, "delegate cannot be null");
        Assert.notNull(users, "users cannot be null");
        this.delegate = delegate;
        this.users = users;
    }

    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request,
                                 HttpServletResponse response) throws SessionAuthenticationException {
        delegate.onAuthentication(underThePersonsEntry(authentication), request, response);
    }

    private Authentication underThePersonsEntry(Authentication authentication) {
        if (authentication.getPrincipal() instanceof UserDetails) {
            return authentication;
        }
        try {
            UserDetails person = users.loadUserByUsername(authentication.getName());
            return UsernamePasswordAuthenticationToken.authenticated(person, null, authentication.getAuthorities());
        } catch (RuntimeException e) {
            // The sign-in itself stands: the session gets its new id, and only the count of this person's sessions
            // misses this one.
            log.warn("Passkey sign-in of '{}': the user store did not give the person's entry, so the limit of "
                    + "sessions does not count this session. Cause: {}", authentication.getName(), e.toString());
            return authentication;
        }
    }
}
