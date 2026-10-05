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
package io.contexa.contexaidentity.security.token.transport;

import io.contexa.contexacommon.properties.AuthContextProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseCookie;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenCookieSameSiteTest {

    @Test
    @DisplayName("Token cookies are SameSite=Lax by default in both cookie transports")
    void laxByDefault() {
        AuthContextProperties properties = new AuthContextProperties();

        assertThat(sameSites(new CookieTokenStrategy(properties).prepareTokensForWrite("access", "refresh")))
                .containsOnly("Lax");
        assertThat(sameSites(new HeaderCookieTokenStrategy(properties).prepareTokensForWrite("access", "refresh")))
                .containsOnly("Lax");
        assertThat(sameSites(new CookieTokenStrategy(properties).prepareTokensForClear()))
                .containsOnly("Lax");
    }

    @Test
    @DisplayName("The configured SameSite value is used regardless of its case")
    void configuredValue() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setCookieSameSite("strict");

        assertThat(sameSites(new CookieTokenStrategy(properties).prepareTokensForWrite("access", "refresh")))
                .containsOnly("Strict");
    }

    @Test
    @DisplayName("An unknown SameSite value fails at startup")
    void unknownValueFails() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setCookieSameSite("Relaxed");

        assertThatThrownBy(() -> new CookieTokenStrategy(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("contexa.auth.cookie-same-site");
    }

    @Test
    @DisplayName("SameSite=None without Secure cookies fails at startup")
    void noneRequiresSecure() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setCookieSameSite("None");
        properties.setCookieSecure(false);

        assertThatThrownBy(() -> new CookieTokenStrategy(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("contexa.auth.cookie-secure=true");
    }

    private static List<String> sameSites(TokenTransportResult result) {
        List<ResponseCookie> cookies = new ArrayList<>();
        if (result.getCookiesToSet() != null) {
            cookies.addAll(result.getCookiesToSet());
        }
        if (result.getCookiesToRemove() != null) {
            cookies.addAll(result.getCookiesToRemove());
        }
        assertThat(cookies).isNotEmpty();
        return cookies.stream().map(ResponseCookie::getSameSite).toList();
    }
}
