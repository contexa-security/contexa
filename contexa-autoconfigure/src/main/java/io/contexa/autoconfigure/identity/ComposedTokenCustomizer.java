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

import io.contexa.contexaidentity.security.core.adapter.state.oauth2.ContexaTokenChecks;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.time.Instant;
import java.util.List;

/**
 * The one token customizer the authorization server sees: Contexa's checks (agent suspension, renewal of a person's
 * token, token exchange) and then the application's customizers in their order. Contexa's run first, so a refusal
 * ends the issuance before any customizer of the application runs and nothing the application does can swallow it; what
 * the application adds to the claims is kept. The limit of lifetime Contexa put on an exchanged token holds after the
 * application's customizers ran: they may shorten the token or lengthen it up to that limit, not beyond it.
 * <p>
 * It is also the {@link ContexaTokenChecks}, Contexa's part alone, for a generator of the application that issues tokens
 * without asking this customizer.
 */
final class ComposedTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext>, ContexaTokenChecks {

    private final OAuth2TokenCustomizer<JwtEncodingContext> contexa;
    private final List<HostTokenCustomizer> application;

    ComposedTokenCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> contexa, List<HostTokenCustomizer> application) {
        this.contexa = contexa;
        this.application = List.copyOf(application);
    }

    @Override
    public void customize(JwtEncodingContext context) {
        contexa.customize(context);
        if (application.isEmpty()) {
            return;
        }
        Instant limit = IdentityOAuth2AutoConfiguration.exchangeLimit(context);
        for (HostTokenCustomizer customizer : application) {
            customizer.customize(context);
        }
        IdentityOAuth2AutoConfiguration.holdToLimit(context, limit);
    }

    @Override
    public void apply(JwtEncodingContext context) {
        contexa.customize(context);
    }
}
