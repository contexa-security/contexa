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

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentDelegationRequest;
import io.contexa.contexacore.autonomous.agent.AgentLearningControl;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.AgentSighting;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexaiam.admin.web.agent.dto.AgentView;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationViews.DelegationView;
import io.contexa.contexaiam.admin.web.agent.service.AgentDelegationService;
import io.contexa.contexaiam.admin.web.agent.service.AgentLearningAdminService;
import io.contexa.contexaiam.admin.web.agent.service.AgentProvisioning;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A1-6 (AM-1, AM-2): the console shows the agents the registry holds, as they are; docs/agent A3-8: an administrator
 * quarantines, releases or removes what an agent learned, and every action is audited.
 */
class AgentAdminControllerTest {

    private final InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
    private final InMemorySecurityContextDataStore contextStore = new InMemorySecurityContextDataStore();
    private final PastRecordQuery records = mock(PastRecordQuery.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final AgentLearningAdminService learning = new AgentLearningAdminService(
            new AgentLearningControl(contextStore, null, () -> records), audit);
    private final InMemoryDelegationRegistry delegationRegistry = new InMemoryDelegationRegistry();
    private final AgentDelegationService delegations = new AgentDelegationService(delegationRegistry, null, audit);
    private final AgentAdminController controller = new AgentAdminController(registry, messages(), learning,
            delegations, AgentProvisioning.unavailable());

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

    /** docs/agent A5-2 (AM-1): each agent's delegations that hold now are counted; ended ones are not. */
    @Test
    @SuppressWarnings("unchecked")
    void theListCountsTheDelegationsThatHoldNow() {
        Instant now = Instant.now();
        delegationRegistry.record(delegation("alice", "agent-7", now.minusSeconds(60), now.plusSeconds(3600)));
        delegationRegistry.record(delegation("bob", "agent-7", now.minusSeconds(60), now.plusSeconds(3600)));
        AgentDelegation revoked = delegationRegistry.record(delegation("carol", "agent-7", now.minusSeconds(60),
                now.plusSeconds(3600)));
        delegationRegistry.revoke(revoked.delegationId(), "carol", "done");
        delegationRegistry.record(delegation("alice", "agent-sp-1", now.plusSeconds(600), now.plusSeconds(3600)));
        ExtendedModelMap model = new ExtendedModelMap();

        controller.list(null, null, model);

        assertThat((Map<String, Integer>) model.get("activeDelegations")).containsExactly(Map.entry("agent-7", 2));
    }

    private static AgentDelegationRequest delegation(String person, String agent, Instant from, Instant until) {
        return new AgentDelegationRequest(null, person, agent, null, "REPORTING", "Weekly report", List.of("READ"),
                List.of(), null, null, null, from, until, null, null);
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
    void theDetailShowsWhetherTheAgentsLearningIsQuarantined() {
        contextStore.setLearningQuarantined("agent:agent-7", true);
        ExtendedModelMap model = new ExtendedModelMap();

        controller.detail("agent-7", null, model, new RedirectAttributesModelMap());

        assertThat(model.get("learningControllable")).isEqualTo(true);
        assertThat(model.get("learningQuarantined")).isEqualTo(true);
        ExtendedModelMap off = new ExtendedModelMap();
        new AgentAdminController(registry, messages(), new AgentLearningAdminService(null, null), delegations,
                AgentProvisioning.unavailable())
                .detail("agent-7", null, off, new RedirectAttributesModelMap());
        assertThat(off.get("learningControllable")).isEqualTo(false);
    }

    @Test
    void anAdministratorQuarantinesTheLearningOfAnAgentAndItIsAudited() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("admin-1", null, List.of()));
        when(records.quarantineAgentRecords("agent-7", "dlg-1")).thenReturn(2);
        RedirectAttributesModelMap redirect = new RedirectAttributesModelMap();

        String view = controller.learning("agent-7", "t-1", "dlg-1", "quarantine", "poisoned delegation", redirect);

        assertThat(view).isEqualTo("redirect:/contexa/admin/agents/detail");
        assertThat(redirect.asMap()).containsEntry("agentId", "agent-7").containsEntry("tenant", "t-1");
        assertThat(redirect.getFlashAttributes()).containsKey("message");
        assertThat(contextStore.learningQuarantined("delegation:dlg-1")).isTrue();
        ArgumentCaptor<AuditRecord> recorded = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(recorded.capture());
        assertThat(recorded.getValue().getEventCategory()).isEqualTo(AuditEventCategory.AGENT_LEARNING_CONTROLLED);
        assertThat(recorded.getValue().getPrincipalName()).isEqualTo("admin-1");
        assertThat(recorded.getValue().getResourceIdentifier()).isEqualTo("agent-7");
        assertThat(recorded.getValue().getAction()).isEqualTo("AGENT_LEARNING_QUARANTINE");
        assertThat(recorded.getValue().getReason()).isEqualTo("poisoned delegation");
        assertThat(recorded.getValue().getDetails()).containsEntry("delegationId", "dlg-1").containsEntry("records", 2);
    }

    @Test
    void anActionWithoutAReasonOrOfAnUnknownKindIsRefusedAndNotAudited() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("admin-1", null, List.of()));
        RedirectAttributesModelMap noReason = new RedirectAttributesModelMap();
        RedirectAttributesModelMap unknown = new RedirectAttributesModelMap();

        controller.learning("agent-7", null, null, "remove", " ", noReason);
        controller.learning("agent-7", null, null, "forget", "why", unknown);

        assertThat(noReason.getFlashAttributes()).containsKey("errorMessage");
        assertThat(unknown.getFlashAttributes()).containsKey("errorMessage");
        assertThat(noReason.asMap()).doesNotContainKey("tenant");
        verify(audit, never()).recordAsync(any());
        verify(records, never()).removeAgentRecords(any(), any());
    }

    /** docs/agent OC-1: the agent's screen shows the delegations people gave it and revokes one with a reason. */
    @Test
    @SuppressWarnings("unchecked")
    void theDetailShowsTheAgentsDelegationsAndAnAdministratorRevokesOne() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("admin-1", null, List.of()));
        AgentDelegation given = delegationRegistry.record(new AgentDelegationRequest(null, "carol", "agent-7", null,
                "REPORTING", "Weekly report", List.of("READ"), List.of("HX-310"), null, null, null, null,
                Instant.now().plus(Duration.ofDays(1)), null, null));
        delegationRegistry.record(new AgentDelegationRequest(null, "carol", "agent-sp-1", null, null, null, null,
                null, null, null, null, null, Instant.now().plus(Duration.ofDays(1)), null, null));
        ExtendedModelMap model = new ExtendedModelMap();

        controller.detail("agent-7", null, model, new RedirectAttributesModelMap());

        assertThat((List<DelegationView>) model.get("delegations")).extracting(DelegationView::delegationId)
                .containsExactly(given.delegationId());
        RedirectAttributesModelMap redirect = new RedirectAttributesModelMap();
        String view = controller.revokeDelegation("agent-7", null, given.delegationId(), "agent hijacked",
                new MockHttpServletRequest(), redirect);

        assertThat(view).isEqualTo("redirect:/contexa/admin/agents/detail");
        assertThat(redirect.getFlashAttributes()).containsKey("message");
        assertThat(delegationRegistry.find(given.delegationId()).orElseThrow().revokedBy()).isEqualTo("admin-1");
        RedirectAttributesModelMap noReason = new RedirectAttributesModelMap();
        controller.revokeDelegation("agent-7", null, given.delegationId(), " ", new MockHttpServletRequest(), noReason);
        assertThat(noReason.getFlashAttributes()).containsKey("errorMessage");
    }

    /** The console takes a delegation back as the admin API does, so it refuses an agent as the admin API does. */
    @Test
    void anAgentHoldingAnAdministratorsTokenRevokesNoDelegationOnTheConsole() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("admin-1", null, List.of()));
        AgentDelegation given = delegationRegistry.record(new AgentDelegationRequest(null, "carol", "agent-7", null,
                "REPORTING", "Weekly report", List.of("READ"), List.of("HX-310"), null, null, null, null,
                Instant.now().plus(Duration.ofDays(1)), null, null));
        MockHttpServletRequest fromAgent = new MockHttpServletRequest();
        fromAgent.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, new DelegationStamp("admin-1", "report-bot",
                true, null, null, null, List.of(), List.of(), null, null, null, null, Map.of()));

        assertThatThrownBy(() -> controller.revokeDelegation("agent-7", null, given.delegationId(), "taken back",
                fromAgent, new RedirectAttributesModelMap()))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        refused -> assertThat(refused.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN));

        assertThat(delegationRegistry.find(given.delegationId()).orElseThrow().revokedAt()).isNull();
    }

    @AfterEach
    void signOut() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void onlyAdministratorsSeeTheAgents() {
        assertThat(AgentAdminController.class.getAnnotation(PreAuthorize.class).value()).isEqualTo("hasAuthority('ROLE_ADMIN')");
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
