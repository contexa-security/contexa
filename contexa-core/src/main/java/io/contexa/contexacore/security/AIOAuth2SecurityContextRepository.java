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

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * OAuth2 token-based Zero Trust repository.
 * Invoked by AIOAuth2ZeroTrustFilter after BearerTokenAuthenticationFilter
 * to apply Zero Trust verification to JWT-authenticated requests.
 *
 * <p>This is NOT registered as a SecurityContextRepository in the filter chain.
 * OAuth2 Resource Server uses NullSecurityContextRepository (stateless).
 * Zero Trust is applied via the dedicated filter instead.
 *
 * @see AIOAuth2ZeroTrustFilter
 * @see AISecurityContextSupport
 */
@Slf4j
public class AIOAuth2SecurityContextRepository implements AISecurityContextRepository {

    private final AISecurityContextSupport support;

    public AIOAuth2SecurityContextRepository(AISecurityContextSupport support) {
        this.support = support;
    }

    /**
     * Apply Zero Trust verification to the current SecurityContext.
     * Called after BearerTokenAuthenticationFilter has set the authentication.
     * Extracts userId from the authenticated principal and delegates to
     * ZeroTrustSecurityService for authority adjustment.
     */
    public void applyZeroTrustToCurrentContext(HttpServletRequest request) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication auth = context.getAuthentication();

        if (!support.isEnabled() || !support.isActuallyAuthenticated(auth)) {
            return;
        }

        String userId = auth.getName();
        String identifier = support.resolveIdentifier(request, auth);

        try {
            support.applyZeroTrust(context, userId, identifier, request);
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to apply Zero Trust for OAuth2 user: {}", userId, e);
        }
    }

    @Override
    public void invalidateAllUserSessions(String userId, String reason) {
        support.invalidateAllUserSessions(userId, reason);
    }
}
