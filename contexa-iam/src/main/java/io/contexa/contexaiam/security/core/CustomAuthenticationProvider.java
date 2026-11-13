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
package io.contexa.contexaiam.security.core;

import io.contexa.contexacommon.security.LocalAccountStatusChecker;
import io.contexa.contexacommon.security.LocalCredentialsVerifier;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final LocalCredentialsVerifier credentials;
    private final LoginPolicyHandler loginPolicyService;

    public CustomAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder,
                                        LoginPolicyHandler loginPolicyService) {
        this.credentials = new LocalCredentialsVerifier(userDetailsService, passwordEncoder);
        this.loginPolicyService = loginPolicyService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();

        loginPolicyService.checkSignInAddress(loginId);

        UserDetails userDetails = credentials.verify(loginId, password);


        LocalAccountStatusChecker.checkAfterCredentials(
                userDetails,
                loginPolicyService.isCredentialsExpired(loginId));

        // The store is Contexa's own where Contexa owns the sign-in, and the application's own (when it has exactly one) where
        // the application keeps it (ContexaUserStore.forSignIn). An account of the application's store is whatever that store
        // returns: taken for one of Contexa's, it failed here with a class cast (500 at every sign-in); it signs in as it is.
        return UsernamePasswordAuthenticationToken.authenticated(userDetails, null, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
