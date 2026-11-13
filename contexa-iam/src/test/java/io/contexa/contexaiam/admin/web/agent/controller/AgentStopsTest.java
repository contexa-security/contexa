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

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.agent.AgentContainmentService;
import io.contexa.contexacore.autonomous.agent.AgentNotice;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.AgentStatus;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentNoticeStore;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexaiam.admin.web.agent.service.AgentContainmentAdminService;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexacore.autonomous.agent.AgentScopeRestriction;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * docs/agent A5-3 (AM-4): the console's agent stops, their admin API and their screen. The stops of agents acting for
 * a person come from the stop records, the agents suspended from the registry; every release and kill switch needs a
 * reason and the autonomous security plane.
 */
class AgentStopsTest {

    private final InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final AuditLogRepository auditLog = mock(AuditLogRepository.class);
    private final InMemoryAgentNoticeStore notices = new InMemoryAgentNoticeStore();
    private final AgentContainmentService containment = new AgentContainmentService(actions, registry, null, null,
            null, mock(CentralAuditFacade.class));
    private final AgentContainmentAdminService service = new AgentContainmentAdminService(containment, registry,
            auditLog, notices);
    private final SpringTemplateEngine engine = engine();

    @Test
    void theStopsOfAgentsActingForAPersonAreTheLatestNotReleasedSince() {
        when(auditLog.findTop500ByEventCategoryInOrderByTimestampDesc(any())).thenReturn(List.of(
                stop("AGENT_RELEASED", "bob", "sync-agent", 12, null),
                stop("AGENT_STOPPED", "alice", "report-agent", 11, "req-91"),
                stop("AGENT_STOPPED", "bob", "sync-agent", 10, "req-80"),
                stop("AGENT_RELEASED", "alice", "report-agent", 9, null),
                stop("AGENT_STOPPED", "alice", "report-agent", 8, "req-70"),
                AuditLog.builder().eventCategory("AGENT_KILL_SWITCH").subjectKind(null).agentId("*")
                        .timestamp(LocalDateTime.of(2026, 10, 24, 7, 0)).build()));
        when(auditLog.findTopByCorrelationIdAndEventCategoryOrderByIdDesc("req-91", "SECURITY_DECISION"))
                .thenReturn(Optional.of(AuditLog.builder().id(345L).build()));

        assertThat(service.stoppedDelegations()).singleElement().satisfies(stop -> {
            assertThat(stop.userId()).isEqualTo("alice");
            assertThat(stop.agentId()).isEqualTo("report-agent");
            assertThat(stop.delegationId()).isEqualTo("DLG-alice");
            assertThat(stop.steps()).isEqualTo("DELEGATION_REVOKED, TOKENS_REVOKED(1)");
            assertThat(stop.decisionRecordId()).isEqualTo(345L);
        });
        assertThat(service.history()).hasSize(6);
    }

    @Test
    void theSuspendedAgentsComeFromTheRegistryAndWithoutTheSecurityPlaneNothingIsActedOn() {
        registry.register(new AgentRegistrationRequest(null, "sync-agent", "Sync", "SYNC", "sync-client", "carol",
                true));
        registry.register(new AgentRegistrationRequest(null, "report-agent", "Report", "REPORTING", "report-client",
                "carol", true));
        registry.suspend(null, "sync-agent", "BLOCK: Bulk export");

        assertThat(service.suspendedAgents()).extracting(agent -> agent.agentId()).containsExactly("sync-agent");
        AgentContainmentAdminService off = new AgentContainmentAdminService(null, registry, null, null);
        assertThat(off.available()).isFalse();
        assertThat(off.stoppedDelegations()).isEmpty();
        assertThat(off.notices()).isEmpty();
        assertThatThrownBy(() -> off.killSwitch(null, null, "admin", "incident"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void theApiActsWithAReasonAndAnswersWhatWasDone() {
        registry.register(new AgentRegistrationRequest(null, "sync-agent", "Sync", "SYNC", "sync-client", "carol",
                true));
        AgentStopApiController api = new AgentStopApiController(service);
        TestingAuthenticationToken admin = new TestingAuthenticationToken("admin", null);

        assertThat(api.act(new StopAction("KILL_SWITCH", null, null, null, " ", null), admin)
                .getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(api.act(new StopAction("RELEASE_DELEGATION", null, null, "report-agent",
                null, "reviewed"), admin).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(api.act(new StopAction("KILL_SWITCH", null, null, null, "SYNC",
                "incident 42"), admin).getBody().agents()).containsExactly("sync-agent");
        assertThat(api.stops().getBody().suspendedAgents()).extracting(agent -> agent.agentId())
                .containsExactly("sync-agent");
        assertThat(api.act(new StopAction("RELEASE_AGENT", null, null, "unknown", null,
                "reviewed"), admin).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(api.act(new StopAction("release_agent", null, null, "sync-agent", null,
                "reviewed"), admin).getBody().success()).isTrue();
        assertThat(registry.find(null, "sync-agent")).map(agent -> agent.status()).contains(AgentStatus.ACTIVE);
        assertThat(new AgentStopApiController(new AgentContainmentAdminService(null, registry, null, null))
                .act(new StopAction("KILL_SWITCH", null, null, null, null, "incident"), admin)
                .getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void theScreenActsWithAReasonAndTellsWhatWasDone() {
        registry.register(new AgentRegistrationRequest(null, "sync-agent", "Sync", "SYNC", "sync-client", "carol",
                true));
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        AgentStopController screen = new AgentStopController(service, messages());
        TestingAuthenticationToken admin = new TestingAuthenticationToken("admin", null);

        RedirectAttributesModelMap applied = new RedirectAttributesModelMap();
        assertThat(screen.killSwitch(null, "", "incident 42", admin, applied))
                .isEqualTo("redirect:/contexa/admin/blacklist/agents");
        assertThat(applied.getFlashAttributes().get("message")).isEqualTo("Kill switch applied: 1 agent(s) suspended.");

        RedirectAttributesModelMap blank = new RedirectAttributesModelMap();
        screen.releaseAgent(null, "sync-agent", " ", admin, blank);
        assertThat(blank.getFlashAttributes()).containsKey("errorMessage");
        assertThat(registry.find(null, "sync-agent")).map(agent -> agent.status()).contains(AgentStatus.SUSPENDED);

        RedirectAttributesModelMap unknown = new RedirectAttributesModelMap();
        screen.releaseAgent(null, "unknown", "reviewed", admin, unknown);
        assertThat(unknown.getFlashAttributes().get("errorMessage")).asString().contains("not registered");

        RedirectAttributesModelMap released = new RedirectAttributesModelMap();
        screen.releaseKillSwitch(null, null, "incident closed", admin, released);
        assertThat(released.getFlashAttributes().get("message"))
                .isEqualTo("Kill switch released: 1 agent(s) resumed.");

        ExtendedModelMap model = new ExtendedModelMap();
        assertThat(screen.stops(model)).isEqualTo("contexa/admin/agent-stops");
        assertThat(model).containsKeys("available", "suspendedAgents", "stoppedDelegations", "history", "notices");
    }

    @AfterEach
    void resetLocale() {
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    void theScreenShowsTheStopsAndTheBlockListLinksItsTabs() {
        registry.register(new AgentRegistrationRequest(null, "sync-agent", "Sync", "SYNC", "sync-client", "carol",
                true));
        registry.suspend(null, "sync-agent", "BLOCK: Bulk export at night");
        notices.save(new AgentNotice("n-1", AgentNotice.AGENT_STOPPED, null, "alice", "report-agent", "DLG-alice",
                "The agent report-agent was stopped while it worked for you", "Contexa stopped the agent.", null,
                "req-91", Instant.parse("2026-10-24T01:00:00Z"), "MAIL", null));
        when(auditLog.findTop500ByEventCategoryInOrderByTimestampDesc(any())).thenReturn(List.of(
                stop("AGENT_STOPPED", "alice", "report-agent", 11, "req-91")));
        when(auditLog.findTopByCorrelationIdAndEventCategoryOrderByIdDesc(eq("req-91"), anyString()))
                .thenReturn(Optional.of(AuditLog.builder().id(345L).build()));
        Map<String, Object> variables = new HashMap<>();
        variables.put("available", true);
        variables.put("suspendedAgents", service.suspendedAgents());
        variables.put("stoppedDelegations", service.stoppedDelegations());
        variables.put("history", service.history());
        variables.put("notices", service.notices());
        variables.put("narrowedAgents", List.of(new AgentScopeRestriction("alice::agent::report-agent", null, "alice",
                "report-agent", EnumSet.of(ActionFamily.READ), "A BLOCK decision (risk 0.95) narrowed the agent to reading",
                "req-91", Instant.parse("2026-10-24T01:00:00Z"), Instant.parse("2026-10-24T02:00:00Z"))));

        String korean = render("contexa/admin/agent-stops", "/contexa/admin/blacklist/agents", Locale.KOREAN,
                variables);
        assertThat(korean).contains("정지된 에이전트", "BLOCK: Bulk export at night", "사람을 대신하다 중지된 에이전트",
                "DELEGATION_REVOKED, TOKENS_REVOKED(1)", "/contexa/admin/security-monitor/345", "킬 스위치",
                "/contexa/admin/blacklist/agents/kill-switch", "/contexa/admin/blacklist/agents/release-delegation",
                "/contexa/admin/blacklist/agents/release-agent", "/contexa/admin/agents/detail?agentId=sync-agent",
                "책임자에게 보낸 알림", ">MAIL<", "판정으로 범위가 좁혀진 에이전트", ">READ<",
                "A BLOCK decision (risk 0.95) narrowed the agent to reading");
        variables.put("available", false);
        variables.put("suspendedAgents", List.of());
        variables.put("stoppedDelegations", List.of());
        variables.put("history", List.of());
        variables.put("notices", List.of());
        variables.put("narrowedAgents", List.of());
        String english = render("contexa/admin/agent-stops", "/contexa/admin/blacklist/agents", Locale.ENGLISH,
                variables);
        assertThat(english).contains("The autonomous security plane is off", "No agent is suspended.",
                "No agent is stopped for a person.", "No agent is narrowed.").doesNotContain("killSwitchForm");

        String blockList = render("contexa/admin/blacklist", "/contexa/admin/blacklist", Locale.KOREAN,
                Map.of("blockedUsers", List.of(), "currentFilter", "all"));
        assertThat(blockList).contains("blacklistTabs", "/contexa/admin/blacklist/agents", ">에이전트<", ">사람<");
    }

    @Test
    void theScreensOfferASessionUnderItsOwnBlockNothingToChange() {
        registry.register(new AgentRegistrationRequest(null, "sync-agent", "Sync", "SYNC", "sync-client", "carol",
                true));
        registry.suspend(null, "sync-agent", "BLOCK: Bulk export at night");
        when(auditLog.findTop500ByEventCategoryInOrderByTimestampDesc(any())).thenReturn(List.of(
                stop("AGENT_STOPPED", "alice", "report-agent", 11, null)));
        Map<String, Object> variables = new HashMap<>();
        variables.put("available", true);
        variables.put("underOwnBlock", true);
        variables.put("suspendedAgents", service.suspendedAgents());
        variables.put("stoppedDelegations", service.stoppedDelegations());
        variables.put("history", service.history());
        variables.put("notices", service.notices());
        variables.put("narrowedAgents", List.of());

        String stops = render("contexa/admin/agent-stops", "/contexa/admin/blacklist/agents", Locale.ENGLISH, variables);
        assertThat(stops).contains("readOnlyNotice", "sync-agent", "report-agent")
                .doesNotContain("/contexa/admin/blacklist/agents/kill-switch", "/contexa/admin/blacklist/agents/release-agent",
                        "/contexa/admin/blacklist/agents/release-delegation");

        BlockedUser resolved = BlockedUser.builder().id(7L).userId("alice").username("alice")
                .status(BlockedUserStatus.RESOLVED).blockCount(1).blockedAt(LocalDateTime.now()).build();
        String list = render("contexa/admin/blacklist", "/contexa/admin/blacklist", Locale.ENGLISH,
                Map.of("blockedUsers", List.of(resolved), "currentFilter", "all", "underOwnBlock", true));
        assertThat(list).contains("readOnlyNotice", "/contexa/admin/blacklist/7")
                .doesNotContain("/contexa/admin/blacklist/challenge-release", "/contexa/admin/blacklist/7/delete");

        String open = render("contexa/admin/blacklist", "/contexa/admin/blacklist", Locale.ENGLISH,
                Map.of("blockedUsers", List.of(resolved), "currentFilter", "all", "underOwnBlock", false));
        assertThat(open).contains("/contexa/admin/blacklist/challenge-release", "/contexa/admin/blacklist/7/delete")
                .doesNotContain("readOnlyNotice");

        BlockedUser blocked = BlockedUser.builder().id(8L).userId("alice").username("alice")
                .status(BlockedUserStatus.BLOCKED).blockCount(1).blockedAt(LocalDateTime.now()).build();
        assertThat(render("contexa/admin/blacklist-detail", "/contexa/admin/blacklist/8", Locale.ENGLISH,
                Map.of("blocked", blocked, "mayLift", false))).doesNotContain("resolveForm\"");
        assertThat(render("contexa/admin/blacklist-detail", "/contexa/admin/blacklist/8", Locale.ENGLISH,
                Map.of("blocked", blocked, "mayLift", true))).contains("/contexa/admin/blacklist/8/resolve");
    }

    private static AuditLog stop(String category, String delegator, String agent, int hour, String correlation) {
        return AuditLog.builder()
                .eventCategory(category)
                .subjectKind("DELEGATED_AGENT")
                .delegatorId(delegator)
                .agentId(agent)
                .delegationId("DLG-" + delegator)
                .principalName("AGENT_STOPPED".equals(category) ? "contexa" : "admin")
                .reason("AGENT_STOPPED".equals(category) ? "Export outside the delegation" : "reviewed")
                .correlationId(correlation)
                .details("AGENT_STOPPED".equals(category)
                        ? "{\"user\":\"" + delegator + "\",\"steps\":\"DELEGATION_REVOKED, TOKENS_REVOKED(1)\"}" : null)
                .timestamp(LocalDateTime.of(2026, 10, 24, hour, 0))
                .build();
    }

    private String render(String template, String path, Locale locale, Map<String, Object> variables) {
        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext, "GET", path);
        WebContext context = new WebContext(JakartaServletWebApplication.buildApplication(servletContext)
                .buildExchange(request, new MockHttpServletResponse()), locale, variables);
        return engine.process(template, context);
    }

    private static ResourceBundleMessageSource messages() {
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setFallbackToSystemLocale(false);
        return messages;
    }

    private static SpringTemplateEngine engine() {
        ClassLoaderTemplateResolver fragments = resolver("test-templates/", 1);
        fragments.setResolvablePatterns(Set.of("contexa/fragments/*"));
        ClassLoaderTemplateResolver templates = resolver("templates/", 2);
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolvers(Set.of(fragments, templates));
        engine.setTemplateEngineMessageSource(messages());
        return engine;
    }

    private static ClassLoaderTemplateResolver resolver(String prefix, int order) {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix(prefix);
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        resolver.setCheckExistence(true);
        resolver.setOrder(order);
        return resolver;
    }
}
