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
package io.contexa.contexaiam.admin.web.agent.controller;

import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexaiam.admin.web.agent.controller.AgentRegistrationApiController.AgentBody;
import io.contexa.contexaiam.admin.web.agent.controller.AgentRegistrationApiController.CredentialsView;
import io.contexa.contexaiam.admin.web.agent.controller.AgentRegistrationApiController.RegisterBody;
import io.contexa.contexaiam.admin.web.agent.dto.AgentView;
import io.contexa.contexaiam.admin.web.agent.service.AgentProvisioning;
import io.contexa.contexaiam.admin.web.agent.service.OAuth2AgentProvisioning;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.RequestMapping;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent OC-3: the admin API registers, rotates, transfers, deregisters and removes agents. */
class AgentRegistrationApiControllerTest {

    private final InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
    private final AgentProvisioning provisioning = new OAuth2AgentProvisioning(registry,
            new InMemoryRegisteredClientRepository(RegisteredClient.withId("portal").clientId("portal")
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build()),
            new BCryptPasswordEncoder(4), null, null, null, null, null, Duration.ofMinutes(30));
    private final AgentRegistrationApiController api = new AgentRegistrationApiController(provisioning, registry);
    private final Authentication admin = new UsernamePasswordAuthenticationToken("admin-1", null, List.of());

    @Test
    void anAgentIsRegisteredActedOnAndListed() {
        var registered = api.register(new RegisterBody(null, "agent/7", "Report agent", null, "carol", null,
                List.of("sc.engineer"), true, true, 15L, false, null), admin);

        assertThat(registered.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        CredentialsView credentials = (CredentialsView) registered.getBody();
        assertThat(credentials.clientId()).isEqualTo("agent/7-client");
        assertThat(credentials.clientSecret()).isNotBlank();
        assertThat(api.list(null, 50)).extracting(AgentView::agentId).containsExactly("agent/7");
        CredentialsView rotated = (CredentialsView) api.rotateSecret(new AgentBody(null, "agent/7", null, null), admin)
                .getBody();
        assertThat(rotated.clientSecret()).isNotEqualTo(credentials.clientSecret());
        assertThat(((AgentView) api.transferSponsor(new AgentBody(null, "agent/7", "dave", null), admin).getBody())
                .sponsorId()).isEqualTo("dave");
        assertThat(api.deregister(new AgentBody(null, "agent/7", null, " "), admin).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(((AgentView) api.deregister(new AgentBody(null, "agent/7", null, "retired"), admin).getBody())
                .status()).isEqualTo("DEREGISTERED");
    }

    @Test
    void mistakesAnswerWithTheirStatus() {
        assertThat(api.register(null, admin).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(api.register(new RegisterBody(null, "agent-1", null, null, null, null, null, null, null, null,
                null, null), admin).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(api.rotateSecret(new AgentBody(null, "nobody", null, null), admin).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
        AgentRegistrationApiController off = new AgentRegistrationApiController(AgentProvisioning.unavailable(),
                registry);
        assertThat(off.register(new RegisterBody(null, "agent-1", null, null, "carol", null, null, null, null, null,
                null, null), admin).getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void onlyAdministratorsReachTheApi() {
        assertThat(AgentRegistrationApiController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo("hasAuthority('ROLE_ADMIN')");
        assertThat(AgentRegistrationApiController.class.getAnnotation(RequestMapping.class).value())
                .containsExactly("/contexa/admin/api/agents");
    }
}
