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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.security.SessionAccountRefresher;
import io.contexa.contexaidentity.security.handler.login.LoginFactsDetails;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** Q-14, Q-13: reading the account again replaces the token of a mail code; the MFA the session completed stays. */
class PasskeyGateAfterAccountRefreshTest {

    private final InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();

    private static UnifiedCustomUserDetails account(String... authorities) {
        Set<GrantedAuthority> granted = new HashSet<>();
        for (String authority : authorities) {
            granted.add(new SimpleGrantedAuthority(authority));
        }
        return new UnifiedCustomUserDetails(UserDto.builder().id(1L).username("alice").enabled(true).build(), granted);
    }

    @Test
    @DisplayName("a session that completed MFA with a code still has it after its account was read again")
    void theMfaOfTheSessionStays() {
        UnifiedCustomUserDetails signedIn = account("ROLE_USER");
        OneTimeTokenAuthenticationToken authentication =
                new OneTimeTokenAuthenticationToken(signedIn, signedIn.getAuthorities());
        authentication.setDetails(new LoginFactsDetails("198.51.100.1", "session-1", List.of("password", "otp"), Instant.now()));
        SecurityContext context = new SecurityContextImpl(authentication);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/webauthn/register/options");
        request.getSession();
        SessionAccountRefresher refresher =
                new SessionAccountRefresher(store, username -> account("ROLE_USER", "ROLE_READER"));
        store.advanceAuthoritiesVersion();

        assertThat(refresher.refresh(context, request, "SPRING_SECURITY_CONTEXT"))
                .isEqualTo(SessionAccountRefresher.Outcome.REFRESHED);

        PasskeyRegistrationGate gate = new PasskeyRegistrationGate(new InMemoryZeroTrustActionRepository(), () -> true, () -> true);
        assertThat(gate.verdict(request, context.getAuthentication())).isEqualTo(PasskeyRegistrationGate.Verdict.OPEN);
    }
}
