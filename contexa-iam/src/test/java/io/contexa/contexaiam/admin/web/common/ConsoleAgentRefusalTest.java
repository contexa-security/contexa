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
package io.contexa.contexaiam.admin.web.common;

import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.agent.AgentContainmentService;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.AgentStatus;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexaiam.admin.web.agent.controller.AgentRegistrationApiController;
import io.contexa.contexaiam.admin.web.agent.controller.AgentStopApiController;
import io.contexa.contexaiam.admin.web.agent.controller.AgentStopController;
import io.contexa.contexaiam.admin.web.agent.service.AgentContainmentAdminService;
import io.contexa.contexaiam.admin.web.agent.service.OAuth2AgentProvisioning;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.util.ServletRequestPathUtils;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * An agent holding an administrator's token is still an agent: the console refuses every request the bridge stamped as
 * an agent's, its pages and its API alike, before any of them acts. A person's request with the same account goes on,
 * and so does an agent's request to the application.
 */
@ExtendWith(I18nTestSupport.EnglishLocale.class)
class ConsoleAgentRefusalTest {

    private static final DelegationStamp AGENT = new DelegationStamp("admin", "report-agent", true, null, null, null,
            List.of(), List.of(), null, null, null, null, Map.of());

    private final InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
    private final AgentContainmentAdminService stops = new AgentContainmentAdminService(
            new AgentContainmentService(new InMemoryZeroTrustActionRepository(), registry, null, null, null,
                    mock(CentralAuditFacade.class)), registry, null, null);
    private final OAuth2AgentProvisioning provisioning = new OAuth2AgentProvisioning(registry,
            new InMemoryRegisteredClientRepository(RegisteredClient.withId("portal").clientId("portal")
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build()),
            new BCryptPasswordEncoder(4), null, null, null, null, null, Duration.ofMinutes(30));
    private MockMvc mvc;

    @BeforeEach
    void aConsoleWithItsAgents() {
        InternalResourceViewResolver views = new InternalResourceViewResolver();
        views.setPrefix("/views/");
        views.setSuffix(".html");
        mvc = MockMvcBuilders.standaloneSetup(new AgentStopApiController(stops),
                        new AgentStopController(stops, I18nTestSupport.englishMessageSource()),
                        new AgentRegistrationApiController(provisioning, registry))
                .addMappedInterceptors(new String[]{ConsoleAgentRefusal.CONSOLE_PATHS}, new ConsoleAgentRefusal())
                .setViewResolvers(views)
                .build();
        registry.register(new AgentRegistrationRequest(null, "report-agent", "Report", "SYNC", "report-client",
                "carol", true));
    }

    @Test
    void anAgentWithAnAdministratorsTokenCannotStopReleaseOrManageAgents() throws Exception {
        asAgent(post("/contexa/admin/api/agents/stops").contentType(MediaType.APPLICATION_JSON)
                .content("{\"action\":\"KILL_SWITCH\",\"reason\":\"incident\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("AGENT_NOT_ALLOWED"));
        asAgent(post("/contexa/admin/blacklist/agents/kill-switch").param("reason", "incident"))
                .andExpect(status().isForbidden());
        asAgent(post("/contexa/admin/api/agents/register").contentType(MediaType.APPLICATION_JSON)
                .content("{\"agentId\":\"rogue-agent\",\"sponsorId\":\"carol\"}"))
                .andExpect(status().isForbidden());
        asAgent(post("/contexa/admin/api/agents/secret").contentType(MediaType.APPLICATION_JSON)
                .content("{\"agentId\":\"report-agent\"}"))
                .andExpect(status().isForbidden());
        // Reading is refused too: the console is a person's.
        asAgent(get("/contexa/admin/api/agents/stops")).andExpect(status().isForbidden());
        asAgent(get("/contexa/admin/api/agents")).andExpect(status().isForbidden());

        assertThat(registry.find(null, "report-agent")).map(agent -> agent.status()).contains(AgentStatus.ACTIVE);
        assertThat(registry.find(null, "rogue-agent")).isEmpty();
    }

    @Test
    void aPersonWithTheSameAccountGoesOn() throws Exception {
        asPerson(get("/contexa/admin/api/agents/stops")).andExpect(status().isOk());
        asPerson(post("/contexa/admin/blacklist/agents/kill-switch").param("reason", "incident"))
                .andExpect(status().is3xxRedirection());

        assertThat(registry.find(null, "report-agent")).map(agent -> agent.status()).contains(AgentStatus.SUSPENDED);
    }

    /** Only the console's paths are refused; what the agent asks of the application is the gate's to decide. */
    @Test
    void theRefusalCoversTheConsoleAndNothingElse() {
        assertThat(ConsoleAgentRefusal.mapped().matches(request("/contexa/admin"))).isTrue();
        assertThat(ConsoleAgentRefusal.mapped().matches(request("/contexa/admin/api/agents/stops"))).isTrue();
        assertThat(ConsoleAgentRefusal.mapped().matches(request("/contexa/admin/users/1"))).isTrue();
        assertThat(ConsoleAgentRefusal.mapped().matches(request("/api/exports"))).isFalse();
        assertThat(ConsoleAgentRefusal.mapped().matches(request("/contexa/api/agent-confirmations"))).isFalse();
    }

    private ResultActions asAgent(MockHttpServletRequestBuilder request) throws Exception {
        return mvc.perform(request.requestAttr(BridgeRequestAttributes.DELEGATION_STAMP, AGENT)
                .principal(new TestingAuthenticationToken("admin", "token", "ROLE_ADMIN")));
    }

    private ResultActions asPerson(MockHttpServletRequestBuilder request) throws Exception {
        return mvc.perform(request.principal(new TestingAuthenticationToken("admin", "password", "ROLE_ADMIN")));
    }

    private static MockHttpServletRequest request(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        ServletRequestPathUtils.parseAndCache(request);
        return request;
    }
}
