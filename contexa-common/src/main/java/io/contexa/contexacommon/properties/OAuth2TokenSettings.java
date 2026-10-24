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
package io.contexa.contexacommon.properties;

import lombok.Data;

import java.util.List;

@Data
public class OAuth2TokenSettings {

    private String clientId = "default-client";
    private String clientSecret;
    private String issuerUri = "http://localhost:9000";
    private String tokenEndpoint = "/oauth2/token";
    private String scope = "read";
    private String redirectUri = "http://localhost:8080";
    private String authorizedUri;

    /**
     * Clients whose own tokens (client credentials: the subject is the client) authenticate without a user account,
     * as service clients with the token's scopes as authorities (A1-2). Approved agents come from the agent registry
     * instead, and the internal client never authenticates this way.
     */
    private List<String> serviceClientIds = List.of();

    /**
     * Whether the token endpoint accepts the RFC 8693 token exchange grant (A1-12): a client registered with the
     * grant, such as an agent's client, exchanges a person's access token (and its own as the actor token) for a
     * token naming the person as the subject and itself as the actor ({@code act}). Off by default: the grant is then
     * refused for every client.
     */
    private boolean tokenExchangeEnabled = false;

    /**
     * docs/agent OC-1: whether a token an agent gets by token exchange for a person names the person's delegation to
     * that agent ({@code delegation_id}), when one holds; the decision then reads that delegation. A token is issued
     * the same with or without one.
     */
    private boolean delegationClaimEnabled = true;

    /**
     * Whether Contexa's resource server accepts only access tokens whose issuer ({@code iss}) is {@code issuer-uri}
     * (A1-7). Checked when {@code issuer-uri} is set; a token from another issuer is refused with 401.
     */
    private boolean issuerValidationEnabled = true;

    /**
     * The audiences ({@code aud}) Contexa's resource server accepts (A1-7): a token must name at least one of them, or
     * it is refused with 401. Contexa's authorization server names the client a token was issued to; list the clients
     * whose tokens this application serves. Empty, the default, does not check the audience.
     */
    private List<String> audiences = List.of();

    private String jwkKeyStorePath;
    private String jwkKeyStorePassword;
    private String jwkKeyAlias;
    private String jwkKeyPassword;
}
