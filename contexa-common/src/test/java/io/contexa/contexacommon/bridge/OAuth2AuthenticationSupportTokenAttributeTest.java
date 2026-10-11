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
package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.OAuth2AuthenticationSupport;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** W1-21: a claim of the token behind an OAuth2 resource server authentication, read as text. */
class OAuth2AuthenticationSupportTokenAttributeTest {

    @Test
    void readsAClaimOfTheTokenAsTrimmedText() {
        JwtAuthenticationToken authentication = token("sid", " login-1 ");

        assertThat(OAuth2AuthenticationSupport.tokenAttribute(authentication, OAuth2AuthenticationSupport.SESSION_ID_CLAIM))
                .isEqualTo("login-1");
    }

    @Test
    void anAbsentOrBlankClaimIsNull() {
        assertThat(OAuth2AuthenticationSupport.tokenAttribute(token("other", "x"), "sid")).isNull();
        assertThat(OAuth2AuthenticationSupport.tokenAttribute(token("sid", "  "), "sid")).isNull();
    }

    @Test
    void anAuthenticationWithoutATokenHasNoTokenAttribute() {
        assertThat(OAuth2AuthenticationSupport.tokenAttribute(
                UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of()), "sid")).isNull();
        assertThat(OAuth2AuthenticationSupport.tokenAttribute(null, "sid")).isNull();
    }

    private static JwtAuthenticationToken token(String name, String value) {
        Instant now = Instant.now();
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject("alice")
                .issuedAt(now).expiresAt(now.plusSeconds(300)).claim(name, value).build();
        return new JwtAuthenticationToken(jwt, List.of());
    }
}
