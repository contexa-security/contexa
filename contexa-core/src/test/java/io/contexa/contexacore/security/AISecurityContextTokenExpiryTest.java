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
package io.contexa.contexacore.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.net.URL;
import java.net.URLClassLoader;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** QF-57: the expiry of the access token behind any OAuth2 token authentication bounds how long its id is tracked. */
class AISecurityContextTokenExpiryTest {

    private final Instant expiresAt = Instant.now().plus(10, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.SECONDS);

    @Test
    void readsTheExpiryOfAnOpaqueBearerTokenAsOfAJwt() {
        OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "opaque-value",
                expiresAt.minus(10, ChronoUnit.MINUTES), expiresAt);
        DefaultOAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal("alice",
                Map.of("sub", "alice"), AuthorityUtils.createAuthorityList("SCOPE_reports.read"));
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject("alice").jti("jti-1")
                .issuedAt(expiresAt.minus(10, ChronoUnit.MINUTES)).expiresAt(expiresAt).build();

        assertThat(AISecurityContextSupport.accessTokenExpiry(
                new BearerTokenAuthentication(principal, token, principal.getAuthorities()))).isEqualTo(expiresAt);
        assertThat(AISecurityContextSupport.accessTokenExpiry(new JwtAuthenticationToken(jwt))).isEqualTo(expiresAt);
    }

    @Test
    void anAuthenticationWithoutATokenHasNoExpiry() {
        assertThat(AISecurityContextSupport.accessTokenExpiry(
                UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of()))).isNull();
        assertThat(AISecurityContextSupport.accessTokenExpiry(null)).isNull();
    }

    @Test
    void withoutTheResourceServerTokenClassesNothingFails() throws Exception {
        String supportName = AISecurityContextSupport.class.getName();
        Set<String> hidden = Set.of(AbstractOAuth2TokenAuthenticationToken.class.getName(),
                JwtAuthenticationToken.class.getName(), BearerTokenAuthentication.class.getName());
        URL classes = AISecurityContextSupport.class.getProtectionDomain().getCodeSource().getLocation();
        try (URLClassLoader isolated = new URLClassLoader(new URL[]{classes}, getClass().getClassLoader()) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (hidden.contains(name)) {
                    throw new ClassNotFoundException(name);
                }
                if (supportName.equals(name)) {
                    Class<?> loaded = findLoadedClass(name);
                    if (loaded == null) {
                        loaded = findClass(name);
                    }
                    if (resolve) {
                        resolveClass(loaded);
                    }
                    return loaded;
                }
                return super.loadClass(name, resolve);
            }
        }) {
            Class<?> supportClass = isolated.loadClass(supportName);
            Object expiry = supportClass.getMethod("accessTokenExpiry", Authentication.class).invoke(null,
                    UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of()));
            assertThat(expiry).isNull();
        }
    }
}
