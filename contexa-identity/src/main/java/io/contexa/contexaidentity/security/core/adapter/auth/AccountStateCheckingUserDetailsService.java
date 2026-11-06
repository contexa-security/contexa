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
package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexacommon.security.LocalAccountStatusChecker;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * The user store of a sign-in that proves the user by something other than the password: a one-time code or a passkey.
 * Spring's providers of those sign-ins read the account and take it as it is, where the password's provider first asks
 * whether the account may sign in at all. This store asks it for them: a locked, disabled or expired account, or one that
 * signs in elsewhere only, is refused as the password refuses it, whatever the code or the key proves. The refusal is
 * an {@link org.springframework.security.core.AuthenticationException}, so the sign-in fails and the success that would
 * reset the account's lock never runs.
 */
public final class AccountStateCheckingUserDetailsService implements UserDetailsService {

    private final UserDetailsService delegate;

    public AccountStateCheckingUserDetailsService(UserDetailsService delegate) {
        Assert.notNull(delegate, "delegate cannot be null");
        this.delegate = delegate;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails account = delegate.loadUserByUsername(username);
        if (account == null) {
            throw new UsernameNotFoundException("No account of this name");
        }
        LocalAccountStatusChecker.checkBeforeCredentials(account);
        return account;
    }
}
