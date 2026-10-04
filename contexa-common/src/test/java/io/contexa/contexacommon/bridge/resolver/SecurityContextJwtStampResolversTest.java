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
package io.contexa.contexacommon.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationDetails;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationToken;
import io.contexa.contexacommon.security.bridge.authentication.BridgePrincipal;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityContextJwtStampResolversTest {

    private final SecurityContextAuthenticationStampResolver authenticationStampResolver = new SecurityContextAuthenticationStampResolver();
    private final SecurityContextAuthorizationStampResolver authorizationStampResolver = new SecurityContextAuthorizationStampResolver();

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void resolversShouldAbsorbJwtClaimsFromSecurityContextWithoutCustomerCustomization() {
        Jwt jwt = Jwt.withTokenValue("header.payload.signature")
                .header("alg", "RS256")
                .claim("sub", "oauth-user-1")
                .claim("name", "OAuth User")
                .claim("organizationId", "tenant-oauth")
                .claim("department", "growth")
                .claim("roles", List.of("ADMIN"))
                .claim("permissions", List.of("REPORT_EXPORT"))
                .claim("scope", "profile reports.read")
                .claim("auth_time", 1711276200L)
                .claim("acr", "loa3")
                .claim("amr", List.of("pwd", "otp"))
                .build();
        JwtAuthenticationToken authentication = new JwtAuthenticationToken(
                jwt,
                List.of(new SimpleGrantedAuthority("SCOPE_profile"), new SimpleGrantedAuthority("SCOPE_reports.read"))
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        RequestContextSnapshot requestContext = new RequestContextSnapshot(
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

        AuthenticationStamp authenticationStamp = authenticationStampResolver.resolve(null, requestContext, new BridgeProperties()).orElseThrow();
        AuthorizationStamp authorizationStamp = authorizationStampResolver.resolve(null, requestContext, new BridgeProperties()).orElseThrow();

        assertThat(authenticationStamp.principalId()).isEqualTo("oauth-user-1");
        assertThat(authenticationStamp.displayName()).isEqualTo("OAuth User");
        assertThat(authenticationStamp.authenticationType()).isEqualTo("JwtAuthenticationToken");
        assertThat(authenticationStamp.authenticationAssurance()).isEqualTo("loa3");
        // amr claim is List type, extractBoolean returns null for non-boolean values
        // MFA detection from amr List requires dedicated resolver logic (future improvement)
        assertThat(authenticationStamp.mfaCompleted()).isNull();
        assertThat(authenticationStamp.authenticationTime()).isEqualTo(Instant.ofEpochSecond(1711276200L));
        assertThat(authenticationStamp.attributes()).containsEntry("organizationId", "tenant-oauth");
        assertThat(authenticationStamp.attributes()).containsEntry("department", "growth");

        assertThat(authorizationStamp.effect()).isEqualTo(AuthorizationEffect.UNKNOWN);
        assertThat(authorizationStamp.effectiveRoles()).contains("ROLE_ADMIN");
        assertThat(authorizationStamp.effectiveAuthorities()).contains("REPORT_EXPORT", "SCOPE_profile", "SCOPE_reports.read");
        // privileged detection from JWT authority claims requires heuristic matching
        // JwtAuthenticationToken authorities (SCOPE_*) do not trigger privileged signal
        assertThat(authorizationStamp.privileged()).isNull();
    }

    @Test
    void jwtPrincipalIdShouldBeTheAuthenticationNameEvenWhenAnEmailClaimIsPresent() {
        Jwt jwt = Jwt.withTokenValue("header.payload.signature")
                .header("alg", "RS256")
                .claim("sub", "u-100")
                .claim("email", "a@corp.com")
                .build();
        JwtAuthenticationToken authentication = new JwtAuthenticationToken(
                jwt,
                List.of(new SimpleGrantedAuthority("SCOPE_profile")));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthenticationStamp authenticationStamp = authenticationStampResolver.resolve(null, requestContext(), new BridgeProperties()).orElseThrow();
        AuthorizationStamp authorizationStamp = authorizationStampResolver.resolve(null, requestContext(), new BridgeProperties()).orElseThrow();

        assertThat(authentication.getName()).isEqualTo("u-100");
        assertThat(authenticationStamp.principalId()).isEqualTo("u-100");
        assertThat(authorizationStamp.subjectId()).isEqualTo("u-100");
    }

    @Test
    void oauth2LoginPrincipalIdShouldBeTheAuthenticationName() {
        DefaultOAuth2User user = new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("OAUTH2_USER")),
                Map.of(
                        "login", "octocat",
                        "id", 583231,
                        "email", "octocat@corp.com"),
                "login");
        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                user,
                user.getAuthorities(),
                "github");
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthenticationStamp authenticationStamp = authenticationStampResolver.resolve(null, requestContext(), new BridgeProperties()).orElseThrow();

        assertThat(authentication.getName()).isEqualTo("octocat");
        assertThat(authenticationStamp.principalId()).isEqualTo("octocat");
        assertThat(authenticationStamp.authenticationType()).isEqualTo("OAuth2AuthenticationToken");
    }

    @Test
    void rewrappedOAuth2PrincipalIdShouldBeTheAuthenticationName() {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("email", "oidc-user@corp.com");
        attributes.put("sub", "oidc-sub-1");
        DefaultOAuth2User user = new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("OIDC_USER")), attributes, "sub");
        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                user, null, user.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthenticationStamp authenticationStamp = authenticationStampResolver.resolve(null, requestContext(), new BridgeProperties()).orElseThrow();

        assertThat(authentication.getName()).isEqualTo("oidc-sub-1");
        assertThat(authenticationStamp.principalId()).isEqualTo("oidc-sub-1");
    }

    @Test
    void userDetailsPrincipalKeepsTheExistingExtractionEvenWhenItIsAnOAuth2Principal() {
        UserDetailsOAuth2Principal principal = new UserDetailsOAuth2Principal();
        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                principal, null, principal.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthenticationStamp authenticationStamp = authenticationStampResolver.resolve(null, requestContext(), new BridgeProperties()).orElseThrow();

        assertThat(authentication.getName()).isEqualTo("alice");
        assertThat(authenticationStamp.principalId()).isEqualTo("u-77");
    }

    @Test
    void bridgeAuthenticationTokenKeepsTheExternalSubjectIdAsPrincipalId() {
        BridgeAuthenticationToken authentication = new BridgeAuthenticationToken(
                new BridgePrincipal("brg_subject", "external-1", "External User", "HUMAN", null, null, null, null,
                        7L, "brg_subject", true, true),
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                bridgeDetails("external-1", "brg_subject"));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthenticationStamp authenticationStamp = authenticationStampResolver.resolve(null, requestContext(), new BridgeProperties()).orElseThrow();

        assertThat(authentication.getName()).isEqualTo("brg_subject");
        assertThat(authenticationStamp.principalId()).isEqualTo("external-1");
    }

    private BridgeAuthenticationDetails bridgeDetails(String externalSubjectId, String internalUsername) {
        return new BridgeAuthenticationDetails(
                "EXPLICIT_HANDOFF", null, null, "AUTHENTICATION_CONTEXT", 40, List.of(), null, List.of(),
                "HANDOFF", null, null, null, null, null, null,
                null, null, null, null, List.of(), List.of(), List.of(),
                null, null, null, null, null, List.of(), List.of(), null, null, null,
                "HUMAN_USER", "DIRECT_USER", "DIRECT", null, null, "HUMAN_SESSION", List.of(),
                7L, internalUsername, internalUsername, externalSubjectId, true, true);
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

    public static class UserDetailsOAuth2Principal implements UserDetails, OAuth2AuthenticatedPrincipal {

        @Override
        public Map<String, Object> getAttributes() {
            return Map.of("userId", "u-77");
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return List.of(new SimpleGrantedAuthority("ROLE_USER"));
        }

        @Override
        public String getName() {
            return "oauth2-name";
        }

        @Override
        public String getPassword() {
            return null;
        }

        @Override
        public String getUsername() {
            return "alice";
        }
    }

    @Test
    void defaultMfaKeysShouldNotIncludeAuthenticationMethodClaimButAttributeKeysShouldKeepIt() {
        BridgeProperties.Authentication.SecurityContext defaults =
                new BridgeProperties().getAuthentication().getSecurityContext();

        assertThat(defaults.getMfaKeys()).doesNotContain("amr");
        assertThat(defaults.getAttributeKeys()).contains("amr");
    }
}
