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
package io.contexa.contexaidentity.security.agent;

import io.contexa.contexacore.autonomous.agent.AgentTokenRevoker;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.DeviceAwareOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * Revokes an agent's tokens on Contexa's authorization server (docs/agent A5-3): the authorizations of the principal
 * (the person the agent acts for, or the agent's client) issued to the agent's client whose tokens still work, a
 * refresh token or none (client credentials, token exchange). Where the application is the authorization server as
 * well, a revoked access token is refused on its next request ({@code OAuth2AuthorizationValidator}); a separate
 * resource server refuses the suspended agent's tokens by the agent directory. The person's own tokens through other
 * clients stay.
 */
public class OAuth2AgentTokenRevoker implements AgentTokenRevoker {

    private final DeviceAwareOAuth2AuthorizationService authorizations;
    private final RegisteredClientRepository clients;

    public OAuth2AgentTokenRevoker(DeviceAwareOAuth2AuthorizationService authorizations,
                                   RegisteredClientRepository clients) {
        this.authorizations = authorizations;
        this.clients = clients;
    }

    @Override
    public int revoke(String principalName, String clientId) {
        if (!StringUtils.hasText(principalName) || !StringUtils.hasText(clientId)) {
            return 0;
        }
        RegisteredClient client = clients.findByClientId(clientId.trim());
        if (client == null) {
            return 0;
        }
        List<OAuth2Authorization> issued = authorizations.findUsableByPrincipalNameAndClient(principalName.trim(),
                client.getId());
        issued.forEach(authorizations::invalidateAuthorization);
        return issued.size();
    }
}
