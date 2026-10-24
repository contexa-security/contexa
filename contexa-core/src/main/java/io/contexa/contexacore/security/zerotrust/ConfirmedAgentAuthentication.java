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
package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;

import java.util.Objects;

/**
 * The authentication an agent's request had before a CHALLENGE narrowed its authorities (docs/agent A5-2). A request
 * the accountable person confirmed runs with its own authorities again, for that request only: the zero trust
 * service keeps the authentication on the request when it narrows an agent's for a CHALLENGE, and the confirmation
 * gate puts it back once the confirmation of that request is used.
 */
public final class ConfirmedAgentAuthentication {

    /** The request attribute the authentication before the narrowing is kept under. */
    public static final String ORIGINAL_AUTHENTICATION = "contexa.zeroTrust.agentAuthenticationBeforeChallenge";

    private ConfirmedAgentAuthentication() {
    }

    /** Keeps the authentication of an agent's request a CHALLENGE is about to narrow. */
    static void keep(@Nullable HttpServletRequest request, @Nullable Authentication authentication) {
        if (request != null && authentication != null && !narrowed(authentication)) {
            request.setAttribute(ORIGINAL_AUTHENTICATION, authentication);
        }
    }

    /**
     * Puts the request's authentication before the narrowing back into the context: the one kept on the request, or,
     * for a session whose stored authentication was narrowed on an earlier request, one with the account's own
     * authorities.
     *
     * @return whether the context holds an authentication that is not narrowed by the CHALLENGE
     */
    public static boolean restore(HttpServletRequest request, SecurityContext context) {
        Authentication current = context.getAuthentication();
        if (current == null) {
            return false;
        }
        if (!narrowed(current)) {
            return true;
        }
        if (request.getAttribute(ORIGINAL_AUTHENTICATION) instanceof Authentication kept
                && Objects.equals(kept.getName(), current.getName())) {
            context.setAuthentication(kept);
            return true;
        }
        if (current.getPrincipal() instanceof UnifiedCustomUserDetails account
                && current instanceof ZeroTrustAuthenticationToken narrowed) {
            ZeroTrustAuthenticationToken restored = new ZeroTrustAuthenticationToken(narrowed.getPrincipal(),
                    narrowed.getCredentials(), account.getOriginalAuthorities(), narrowed.getTrustScore(),
                    narrowed.getThreatScore(), ZeroTrustAction.ALLOW);
            restored.setDetails(narrowed.getDetails());
            context.setAuthentication(restored);
            return true;
        }
        return false;
    }

    /** Whether the authentication carries the CHALLENGE's authority only. */
    private static boolean narrowed(Authentication authentication) {
        String challenge = ZeroTrustAction.CHALLENGE.getGrantedAuthority();
        return authentication.getAuthorities().stream()
                .anyMatch(authority -> challenge.equals(authority.getAuthority()));
    }
}
