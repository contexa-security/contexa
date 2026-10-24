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

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent A5-2: an agent's request its accountable person confirmed runs with its own authorities again, not with
 * the CHALLENGE's narrowed one, for that request only.
 */
class ConfirmedAgentAuthenticationTest {

    private static final SimpleGrantedAuthority CHALLENGE =
            new SimpleGrantedAuthority(ZeroTrustAction.CHALLENGE.getGrantedAuthority());

    @Test
    void aTokenRequestGetsTheAuthenticationItHadBeforeTheChallenge() {
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject("alice")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(300)).build();
        JwtAuthenticationToken original = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("SCOPE_reports.read")), "alice");
        MockHttpServletRequest request = new MockHttpServletRequest();
        ConfirmedAgentAuthentication.keep(request, original);
        SecurityContext context = new SecurityContextImpl(new JwtAuthenticationToken(jwt, List.of(CHALLENGE),
                "alice"));

        assertThat(ConfirmedAgentAuthentication.restore(request, context)).isTrue();

        assertThat(context.getAuthentication()).isSameAs(original);
    }

    @Test
    void aSessionNarrowedOnAnEarlierRequestGetsTheAccountsOwnAuthorities() {
        Set<GrantedAuthority> own = Set.of(new SimpleGrantedAuthority("ROLE_AGENT"));
        UnifiedCustomUserDetails account = new UnifiedCustomUserDetails(UserDto.builder().username("sync-agent")
                .password("n/a").build(), own);
        SecurityContext context = new SecurityContextImpl(new ZeroTrustAuthenticationToken(account, null,
                List.of(CHALLENGE), 0.4, 0.6, ZeroTrustAction.CHALLENGE));
        MockHttpServletRequest request = new MockHttpServletRequest();
        // The request kept the session's authentication, already narrowed: it is not taken back.
        ConfirmedAgentAuthentication.keep(request, context.getAuthentication());

        assertThat(ConfirmedAgentAuthentication.restore(request, context)).isTrue();

        Authentication restored = context.getAuthentication();
        assertThat(restored.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsExactly("ROLE_AGENT");
        assertThat(((ZeroTrustAuthenticationToken) restored).getAction()).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    void nothingIsTakenBackForAnotherUserOrWithoutAKeptAuthentication() {
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject("alice")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(300)).build();
        MockHttpServletRequest request = new MockHttpServletRequest();
        ConfirmedAgentAuthentication.keep(request, new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("SCOPE_admin")), "mallory"));
        SecurityContext context = new SecurityContextImpl(new JwtAuthenticationToken(jwt, List.of(CHALLENGE),
                "alice"));

        assertThat(ConfirmedAgentAuthentication.restore(request, context)).isFalse();
        assertThat(context.getAuthentication().getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactly(CHALLENGE.getAuthority());
    }
}
