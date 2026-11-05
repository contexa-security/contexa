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
package io.contexa.contexacommon.security;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.UUID;

/**
 * The password check of a local sign-in, shared by the providers of the form and REST flows. A sign-in must not tell
 * whether an account exists: a name without an account fails with the words of a wrong password, and every refusal
 * costs one password comparison, because the hashing is what a stopwatch would otherwise tell apart.
 */
public final class LocalCredentialsVerifier {

    /** The words of a refused sign-in. Every flow answers with them, whatever refused it. */
    public static final String SIGN_IN_REFUSED = "Invalid username or password.";

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private volatile String decoyHash;

    public LocalCredentialsVerifier(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Returns the account when its state allows a sign-in and the password is right.
     *
     * @throws AuthenticationException the refusal; the type says why to the caller's records, not to the person
     */
    public UserDetails verify(String loginId, @Nullable String password) {
        prepareDecoy();
        UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(loginId);
        } catch (UsernameNotFoundException unknown) {
            compareWithDecoy(password);
            throw new BadCredentialsException(SIGN_IN_REFUSED);
        }
        try {
            LocalAccountStatusChecker.checkBeforeCredentials(userDetails);
        } catch (AuthenticationException refused) {
            compareWithDecoy(password);
            throw refused;
        }
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException(SIGN_IN_REFUSED);
        }
        return userDetails;
    }

    /** Before the account is looked up, so that the first sign-in costs the same whether it exists or not. */
    private void prepareDecoy() {
        if (decoyHash == null) {
            decoyHash = passwordEncoder.encode(UUID.randomUUID().toString());
        }
    }

    private void compareWithDecoy(@Nullable String password) {
        if (password != null && decoyHash != null) {
            passwordEncoder.matches(password, decoyHash);
        }
    }
}
