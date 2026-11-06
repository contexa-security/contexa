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
package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacommon.security.LocalAccountStatusChecker;
import io.contexa.contexacommon.security.LocalCredentialsVerifier;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class RestAuthenticationProvider implements AuthenticationProvider {

    private final LocalCredentialsVerifier credentials;
    @Nullable
    private final LoginPolicyHandler loginPolicyHandler;

    public RestAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder,
                                      @Nullable LoginPolicyHandler loginPolicyHandler) {
        this.credentials = new LocalCredentialsVerifier(userDetailsService, passwordEncoder);
        this.loginPolicyHandler = loginPolicyHandler;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();

        if (loginPolicyHandler != null) {
            loginPolicyHandler.checkSignInAddress(loginId);
            loginPolicyHandler.checkAndUnlockIfExpired(loginId);
        }

        UserDetails userDetails = credentials.verify(loginId, password);

        boolean policyCredentialsExpired = loginPolicyHandler != null
                && loginPolicyHandler.isCredentialsExpired(loginId);
        LocalAccountStatusChecker.checkAfterCredentials(userDetails, policyCredentialsExpired);

        return RestAuthenticationToken.authenticated(userDetails, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return RestAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
