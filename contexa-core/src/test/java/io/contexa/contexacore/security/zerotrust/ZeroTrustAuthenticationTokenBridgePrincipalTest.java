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
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Zero Trust service replaces a session OAuth2/OIDC login with a {@link ZeroTrustAuthenticationToken}
 * that keeps the principal. The bridge principal id must still be the name Zero Trust keys its decisions by.
 */
class ZeroTrustAuthenticationTokenBridgePrincipalTest {

    private final SecurityContextAuthenticationStampResolver resolver = new SecurityContextAuthenticationStampResolver();

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void zeroTrustWrappedOAuth2LoginUsesTheOAuth2UserName() {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("email", "oidc-user@corp.com");
        attributes.put("sub", "oidc-sub-1");
        DefaultOAuth2User user = new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("OIDC_USER")), attributes, "sub");
        ZeroTrustAuthenticationToken authentication = new ZeroTrustAuthenticationToken(
                user, null, List.of(new SimpleGrantedAuthority("ROLE_MFA_REQUIRED")), 0.4, 0.6, ZeroTrustAction.CHALLENGE);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthenticationStamp stamp = resolver.resolve(null, requestContext(), new BridgeProperties()).orElseThrow();

        assertThat(authentication.getName()).isEqualTo("oidc-sub-1");
        assertThat(stamp.principalId()).isEqualTo("oidc-sub-1");
    }

    @Test
    void zeroTrustWrappedUserDetailsKeepsTheUsername() {
        UserDetails user = User.withUsername("alice").password("n/a").authorities("ROLE_USER").build();
        ZeroTrustAuthenticationToken authentication = new ZeroTrustAuthenticationToken(
                user, null, user.getAuthorities(), 0.9, 0.1, ZeroTrustAction.ALLOW);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthenticationStamp stamp = resolver.resolve(null, requestContext(), new BridgeProperties()).orElseThrow();

        assertThat(stamp.principalId()).isEqualTo("alice");
    }

    private RequestContextSnapshot requestContext() {
        return new RequestContextSnapshot(
                "/api/profile",
                "GET",
                "127.0.0.1",
                "JUnit",
                null,
                "request-1",
                "/api/profile",
                null,
                false,
                Instant.now()
        );
    }
}
