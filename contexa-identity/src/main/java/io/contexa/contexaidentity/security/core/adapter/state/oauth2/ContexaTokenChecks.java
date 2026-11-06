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

import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

/**
 * Contexa's own checks on the tokens its authorization server issues, apart from any customizer of the application: the
 * refusal of a suspended agent's token, of the renewal of a person's token the account or a decision in force stops, and
 * the rules of a token exchange (scope, lifetime, no exchange of an exchanged token), together with the claims and the limit
 * of lifetime they write. The authorization server finds them in the one token customizer it takes; where an application
 * issues its tokens with a generator of its own the server never offers a token to a customizer, and a
 * {@link CheckedTokenGenerator} asks them of this instead. A bean of this type is a customizer in none of the server's
 * lookups.
 */
@FunctionalInterface
public interface ContexaTokenChecks {

    /**
     * Runs the checks on the token about to be issued. A refusal is an {@code OAuth2AuthenticationException}, and nothing the
     * application does can swallow it. What the checks write into the claims is what Contexa's tokens carry.
     */
    void apply(JwtEncodingContext context);
}
