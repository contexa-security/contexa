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

import io.contexa.contexacommon.domain.UserDto;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** PR-42, on a real password hash: each way a sign-in fails costs exactly one comparison, the work a stopwatch sees. */
class LocalCredentialsVerifierTest {

    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(4);
    private final AtomicInteger comparisons = new AtomicInteger();
    private final PasswordEncoder countingEncoder = new PasswordEncoder() {
        @Override
        public String encode(CharSequence rawPassword) {
            return bcrypt.encode(rawPassword);
        }

        @Override
        public boolean matches(CharSequence rawPassword, String encodedPassword) {
            comparisons.incrementAndGet();
            return bcrypt.matches(rawPassword, encodedPassword);
        }
    };
    private final String hash = bcrypt.encode("right");
    private final Map<String, UserDetails> accounts = Map.of(
            "alice", account("alice", true, false, false),
            "locked", account("locked", true, true, false),
            "disabled", account("disabled", false, false, false),
            "bridged", account("bridged", true, false, true));
    private final UserDetailsService users = username -> {
        UserDetails account = accounts.get(username);
        if (account == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        return account;
    };
    private final LocalCredentialsVerifier verifier = new LocalCredentialsVerifier(users, countingEncoder);

    @Test
    @DisplayName("The right password of an active account is accepted")
    void acceptsTheRightPassword() {
        assertThat(verifier.verify("alice", "right").getUsername()).isEqualTo("alice");
        assertThat(comparisons).hasValue(1);
    }

    @Test
    @DisplayName("A name without an account fails like a wrong password and keeps the name out of the failure")
    void anUnknownNameFailsLikeAWrongPassword() {
        assertThatThrownBy(() -> verifier.verify("ghost", "wrong"))
                .isExactlyInstanceOf(BadCredentialsException.class)
                .hasMessage(LocalCredentialsVerifier.SIGN_IN_REFUSED)
                .hasMessageNotContaining("ghost")
                .hasNoCause();
        assertThat(comparisons).hasValue(1);

        comparisons.set(0);
        assertThatThrownBy(() -> verifier.verify("alice", "wrong"))
                .isExactlyInstanceOf(BadCredentialsException.class)
                .hasMessage(LocalCredentialsVerifier.SIGN_IN_REFUSED);
        assertThat(comparisons).hasValue(1);
    }

    @Test
    @DisplayName("A refused account costs the comparison a wrong password costs, and keeps its reason for the records")
    void aRefusedAccountCostsOneComparison() {
        assertThatThrownBy(() -> verifier.verify("locked", "right")).isInstanceOf(LockedException.class);
        assertThat(comparisons).hasValue(1);

        comparisons.set(0);
        assertThatThrownBy(() -> verifier.verify("disabled", "right")).isInstanceOf(DisabledException.class);
        assertThat(comparisons).hasValue(1);

        comparisons.set(0);
        assertThatThrownBy(() -> verifier.verify("bridged", "right"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("External authentication only account");
        assertThat(comparisons).hasValue(1);
    }

    @Test
    @DisplayName("A sign-in without a password fails like any other for a name without an account")
    void aMissingPasswordOfAnUnknownNameIsRefused() {
        assertThatThrownBy(() -> verifier.verify("ghost", null))
                .isExactlyInstanceOf(BadCredentialsException.class)
                .hasMessage(LocalCredentialsVerifier.SIGN_IN_REFUSED);
    }

    private UserDetails account(String username, boolean enabled, boolean locked, boolean externalOnly) {
        return new UnifiedCustomUserDetails(UserDto.builder()
                .username(username)
                .password(hash)
                .enabled(enabled)
                .accountLocked(locked)
                .externalAuthOnly(externalOnly)
                .build(), Set.of());
    }
}
