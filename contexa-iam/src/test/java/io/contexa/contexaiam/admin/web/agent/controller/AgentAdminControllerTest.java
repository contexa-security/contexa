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

import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.AgentSighting;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexaiam.admin.web.agent.dto.AgentView;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** A1-6 (AM-1, AM-2): the console shows the agents the registry holds, as they are. */
class AgentAdminControllerTest {

    private final InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
    private final AgentAdminController controller = new AgentAdminController(registry, messages());

    @BeforeEach
    void setUp() {
        registry.observe(new AgentSighting(null, "agent-7", "DELEGATED_AGENT", "agent-client",
                Instant.parse("2026-10-22T03:00:00Z")));
        registry.register(new AgentRegistrationRequest(null, "agent-7", "Report assistant", "report-blueprint",
                null, "carol", null));
        registry.observe(new AgentSighting(null, "agent-sp-1", "AUTONOMOUS_AGENT", null,
                Instant.parse("2026-10-22T04:00:00Z")));
        registry.register(new AgentRegistrationRequest(null, "agent-old", "Retired bot", null, null, "dave", null));
        registry.deregister(null, "agent-old", "offboarded");
    }

    @Test
    void theListShowsEveryAgentLatestSeenFirst() {
        ExtendedModelMap model = new ExtendedModelMap();

        String view = controller.list(null, null, model);

        assertThat(view).isEqualTo("contexa/admin/agents");
        assertThat(agents(model)).extracting(AgentView::agentId).containsExactly("agent-sp-1", "agent-7", "agent-old");
        AgentView registered = agents(model).get(1);
        assertThat(registered.displayName()).isEqualTo("Report assistant");
        assertThat(registered.sponsorId()).isEqualTo("carol");
        assertThat(registered.subjectKind()).isEqualTo("DELEGATED_AGENT");
        assertThat(registered.allowlisted()).isTrue();
        assertThat(registered.firstSeenAt()).isNotNull();
        assertThat(model.get("currentFilter")).isEqualTo("all");
    }

    @Test
    void theListFiltersByStatusAndKeyword() {
        ExtendedModelMap deregistered = new ExtendedModelMap();
        ExtendedModelMap unregistered = new ExtendedModelMap();
        ExtendedModelMap byKeyword = new ExtendedModelMap();

        controller.list("deregistered", null, deregistered);
        controller.list("observed", null, unregistered);
        controller.list(null, "CAROL", byKeyword);

        assertThat(agents(deregistered)).extracting(AgentView::agentId).containsExactly("agent-old");
        // Observed only: no identity provider registered it.
        assertThat(agents(unregistered)).extracting(AgentView::agentId).containsExactly("agent-sp-1");
        assertThat(agents(byKeyword)).extracting(AgentView::agentId).containsExactly("agent-7");
    }

    @Test
    void theDetailShowsOneAgentAndAnUnknownOneGoesBackToTheList() {
        ExtendedModelMap model = new ExtendedModelMap();
        RedirectAttributesModelMap redirect = new RedirectAttributesModelMap();

        String view = controller.detail("agent-old", null, model, new RedirectAttributesModelMap());
        String missing = controller.detail("agent-nobody", null, new ExtendedModelMap(), redirect);

        assertThat(view).isEqualTo("contexa/admin/agent-detail");
        AgentView agent = (AgentView) model.get("agent");
        assertThat(agent.status()).isEqualTo("DEREGISTERED");
        assertThat(agent.statusReason()).isEqualTo("offboarded");
        assertThat(agent.deregisteredAt()).isNotNull();
        assertThat(missing).isEqualTo("redirect:/contexa/admin/agents");
        assertThat(redirect.getFlashAttributes()).containsKey("errorMessage");
    }

    @Test
    void onlyAdministratorsSeeTheAgents() {
        assertThat(AgentAdminController.class.getAnnotation(PreAuthorize.class).value()).isEqualTo("hasRole('ADMIN')");
    }

    private static StaticMessageSource messages() {
        StaticMessageSource messages = new StaticMessageSource();
        messages.setUseCodeAsDefaultMessage(true);
        return messages;
    }

    @SuppressWarnings("unchecked")
    private static List<AgentView> agents(ExtendedModelMap model) {
        return (List<AgentView>) model.get("agents");
    }
}
