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
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A1-7: Contexa's ALLOW never widens what a token grants; an agent's token keeps exactly its authorities, and the other
 * actions only take authorities away or mark the request.
 */
class ZeroTrustAllowKeepsTokenAuthoritiesTest {

    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final InMemoryZeroTrustSecurityService service = new InMemoryZeroTrustSecurityService(
            mock(ThreatScoreUtil.class), new SecurityZeroTrustProperties(), actions, null);

    @Test
    void allowKeepsExactlyTheTokensAuthorities() {
        SecurityContext context = context("report-client", "SCOPE_reports.read");
        when(actions.getCurrentAction(eq("report-client"), any())).thenReturn(ZeroTrustAction.ALLOW);

        service.applyZeroTrustToContext(context, "report-client", null, new MockHttpServletRequest());

        assertThat(authorities(context)).containsExactly("SCOPE_reports.read");
    }

    @Test
    void theOtherActionsOnlyNarrowOrMark() {
        for (ZeroTrustAction action : new ZeroTrustAction[]{ZeroTrustAction.CHALLENGE, ZeroTrustAction.BLOCK,
                ZeroTrustAction.ESCALATE, ZeroTrustAction.PENDING_ANALYSIS}) {
            SecurityContext context = context("agent-" + action.name(), "SCOPE_reports.read");
            when(actions.getCurrentAction(eq("agent-" + action.name()), any())).thenReturn(action);

            service.applyZeroTrustToContext(context, "agent-" + action.name(), null, new MockHttpServletRequest());

            Set<String> granted = authorities(context);
            granted.remove(action.getGrantedAuthority());
            assertThat(granted).as(action.name()).isSubsetOf("SCOPE_reports.read");
        }
    }

    private static SecurityContext context(String subject, String... authorities) {
        Instant now = Instant.now();
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject(subject).claim("client_id", subject)
                .issuedAt(now).expiresAt(now.plusSeconds(300)).build();
        return new SecurityContextImpl(new JwtAuthenticationToken(jwt, AuthorityUtils.createAuthorityList(authorities)));
    }

    private static Set<String> authorities(SecurityContext context) {
        return context.getAuthentication().getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }
}
