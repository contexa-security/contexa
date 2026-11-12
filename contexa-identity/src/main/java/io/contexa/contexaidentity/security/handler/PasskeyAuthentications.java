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
package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexaidentity.security.filter.RestAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import io.contexa.contexaidentity.security.handler.login.LoginFactsRecorder;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * A passkey sign-in as a sign-in of the Contexa account. Spring's passkey filter leaves its credential user entity as the
 * principal; read as a principal of a host application, it made a second account of the person ("brg_...") and
 * serialized poorly. The MFA passkey factor turned it into the account; the passkey sign-in alone did not.
 */
@Slf4j
public final class PasskeyAuthentications {

    private PasskeyAuthentications() {
    }

    /** The sign-in with the Contexa account as its principal, or the sign-in as it is when it is no passkey's. */
    public static Authentication asContexaAccount(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof ImmutablePublicKeyCredentialUserEntity entity) {
            try {
                UserDto account = UserDto.builder().username(entity.getName()).build();
                Set<GrantedAuthority> authorities = new HashSet<>((Collection<? extends GrantedAuthority>) authentication.getAuthorities());
                return RestAuthenticationToken.authenticated(new UnifiedCustomUserDetails(account, authorities),
                        authentication.getAuthorities());
            } catch (RuntimeException e) {
                log.error("A passkey sign-in could not be turned into a sign-in of the Contexa account; it stays as it is", e);
            }
        }
        return authentication;
    }

    /**
     * The success handler of a passkey sign-in alone: the sign-in of the request (already in the security context the
     * filter saved) becomes the account's before the handler answers.
     */
    public static AuthenticationSuccessHandler asContexaAccountFirst(AuthenticationSuccessHandler handler) {
        return (request, response, authentication) -> {
            // The login's facts are a passkey's: recorded before the sign-in becomes the account's, whose class would
            // read as a password, and carried over to it.
            LoginFactsRecorder.recordSingleFactor(authentication, request);
            Authentication account = asContexaAccount(authentication);
            if (account != authentication) {
                if (account instanceof AbstractAuthenticationToken token) {
                    token.setDetails(authentication.getDetails());
                }
                SecurityContextHolder.getContext().setAuthentication(account);
            }
            handler.onAuthenticationSuccess(request, response, account);
        };
    }
}
