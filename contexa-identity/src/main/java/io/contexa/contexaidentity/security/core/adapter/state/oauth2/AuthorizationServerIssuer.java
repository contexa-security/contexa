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
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import io.contexa.contexacommon.properties.OAuth2TokenSettings;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.util.StringUtils;

/**
 * The issuer of Contexa's tokens, one rule for the chain that issues them and the decoder that checks them.
 * <p>
 * The settings bean need not be Contexa's: Spring Boot makes one with no issuer as soon as the authorization server library
 * is on the class path, and Contexa's own then steps back. Without an issuer in the settings Spring takes it from the
 * request, and a login issues its token inside the request of the login, so the token would name the login's path.
 */
public final class AuthorizationServerIssuer {

    private AuthorizationServerIssuer() {
    }

    /**
     * The issuer the settings name, or else {@code contexa.auth.oauth2.issuer-uri}. Null with several issuers on one host:
     * each request then has its own, and no single one can be expected.
     */
    @Nullable
    public static String of(@Nullable AuthorizationServerSettings settings, OAuth2TokenSettings oauth2) {
        if (settings != null && settings.isMultipleIssuersAllowed()) {
            return null;
        }
        return settings != null && StringUtils.hasText(settings.getIssuer()) ? settings.getIssuer() : oauth2.getIssuerUri();
    }

    /** The settings with the issuer of {@link #of}; settings that have it, or for which there is none, come back as they are. */
    public static AuthorizationServerSettings applyTo(AuthorizationServerSettings settings, OAuth2TokenSettings oauth2) {
        String issuer = of(settings, oauth2);
        if (!StringUtils.hasText(issuer) || issuer.equals(settings.getIssuer())) {
            return settings;
        }
        return AuthorizationServerSettings.withSettings(settings.getSettings()).issuer(issuer).build();
    }
}
