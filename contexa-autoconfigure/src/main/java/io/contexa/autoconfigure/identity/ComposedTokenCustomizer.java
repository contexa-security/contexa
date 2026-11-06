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
package io.contexa.autoconfigure.identity;

import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.List;

/**
 * The one token customizer the authorization server sees: Contexa's checks (agent suspension, renewal of a person's
 * token, token exchange) and then the application's customizers in their order. Contexa's run first, so a refusal
 * ends the issuance before any customizer of the application runs and nothing the application does can swallow it; what
 * the application adds to the claims is kept.
 */
final class ComposedTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final OAuth2TokenCustomizer<JwtEncodingContext> contexa;
    private final List<HostTokenCustomizer> application;

    ComposedTokenCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> contexa, List<HostTokenCustomizer> application) {
        this.contexa = contexa;
        this.application = List.copyOf(application);
    }

    @Override
    public void customize(JwtEncodingContext context) {
        contexa.customize(context);
        for (HostTokenCustomizer customizer : application) {
            customizer.customize(context);
        }
    }
}
