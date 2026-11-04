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
package io.contexa.contexaiam.agent.web;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.agent.AgentConfirmation;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationService;
import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentDelegationRequest;
import io.contexa.contexacore.autonomous.agent.AgentRequestBinding;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentConfirmationStore;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import io.contexa.contexacore.autonomous.agent.SignedAgentConfirmationAuthorizer;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.agent.AgentContainmentService;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.AgentStatus;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexaiam.admin.web.agent.service.AgentContainmentAdminService;
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
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * docs/agent A5-2 (AC-1~AC-3): the person the confirmation is for decides it in their own session, never an agent
 * with the person's token; the page shows what was delegated, what the agent asks and why, and then the result with
 * its record; the agent reads only its own confirmations.
 */
class AgentConfirmationPagesTest {

    private static final ZeroTrustSubject AGENT = new ZeroTrustSubject(null, "alice", SubjectKind.DELEGATED_AGENT,
            "report-agent", null);

    private final InMemoryAgentConfirmationStore store = new InMemoryAgentConfirmationStore();
    private final AgentConfirmationService service = new AgentConfirmationService(store,
            new SignedAgentConfirmationAuthorizer(HmacEvidenceSigner.of(Map.of("k1", Base64.getEncoder()
                    .encodeToString("0123456789abcdef0123456789abcdef".getBytes())), "k1")), null, null, null,
            Duration.ofMinutes(15), null);
    private final InMemoryDelegationRegistry delegations = new InMemoryDelegationRegistry();
    private final AuditLogRepository records = mock(AuditLogRepository.class);
    private final AgentConfirmationController pages = new AgentConfirmationController(service, messages());
    private final SpringTemplateEngine engine = engine();

    @AfterEach
    void resetLocale() {
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    void onlyThePersonDecidesInTheirOwnSessionNeverAnAgent() {
        String id = ask().confirmationId();
        TestingAuthenticationToken alice = new TestingAuthenticationToken("alice", null);
        MockHttpServletRequest agentRequest = new MockHttpServletRequest("POST", "/contexa/agent-confirmations/" + id);
        agentRequest.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, new DelegationStamp("alice",
                "report-agent", true, null, null, null, List.of(), List.of(), null, null, null, null, Map.of()));

        assertThatThrownBy(() -> pages.approve(id, null, alice, agentRequest, new RedirectAttributesModelMap()))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN));
        assertThatThrownBy(() -> pages.approve(id, null, new TestingAuthenticationToken("mallory", null),
                new MockHttpServletRequest(), new RedirectAttributesModelMap()))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND));
        assertThat(store.find(id)).map(AgentConfirmation::status).contains(AgentConfirmation.Status.PENDING);

        LocaleContextHolder.setLocale(Locale.ENGLISH);
        RedirectAttributesModelMap done = new RedirectAttributesModelMap();
        assertThat(pages.approve(id, "expected", alice, new MockHttpServletRequest(), done))
                .isEqualTo("redirect:/contexa/agent-confirmations/" + id);
        assertThat(done.getFlashAttributes().get("message"))
                .isEqualTo("Approved. The agent may send the request once.");
        RedirectAttributesModelMap twice = new RedirectAttributesModelMap();
        pages.reject(id, null, alice, new MockHttpServletRequest(), twice);
        assertThat(twice.getFlashAttributes()).containsKey("errorMessage");
        assertThat(store.find(id)).map(AgentConfirmation::status).contains(AgentConfirmation.Status.APPROVED);
    }

    @Test
    void thePageShowsTheDelegationTheRequestAndWhyAndThenTheResult() {
        AgentDelegation delegation = delegations.record(new AgentDelegationRequest(null, "alice", "report-agent", null,
                "REPORTING", "Export this week's HX-310 design review packages", List.of("EXPORT"),
                List.of("HX-310"), null, null, null, Instant.now().minusSeconds(3600),
                Instant.now().plus(Duration.ofDays(2)), null, null));
        pages.setDelegations(delegations);
        pages.setDecisionRecords(records);
        when(records.findTop10ByAgentIdAndEventCategoryOrderByTimestampDesc("report-agent", "SECURITY_DECISION"))
                .thenReturn(List.of(AuditLog.builder().id(7L).agentId("report-agent").delegatorId("alice")
                        .decision("CHALLENGE").reason("The agent exports a project outside the delegation")
                        .riskState("DELEGATION_SCOPE_DRIFT(F13), UsualClients(new)")
                        .timestamp(LocalDateTime.now(ZoneId.systemDefault()).minusMinutes(1)).build()));
        AgentConfirmation asked = service.request(new AgentConfirmationService.ConfirmationRequest(AGENT, "hash-1",
                "POST", "/api/exports?project=GB-500", AgentConfirmation.DECISION_CHALLENGE, null, "req-1",
                null)).orElseThrow();
        TestingAuthenticationToken alice = new TestingAuthenticationToken("alice", null);

        ExtendedModelMap model = new ExtendedModelMap();
        assertThat(pages.confirmation(asked.confirmationId(), alice, new MockHttpServletRequest(), model))
                .isEqualTo("contexa/agent-confirmation");
        assertThat(model.get("delegation")).isEqualTo(delegation);
        String korean = render("contexa/agent-confirmation", Locale.KOREAN, model);
        assertThat(korean).contains("에이전트 요청 확인", "report-agent", "POST /api/exports?project=GB-500",
                "Export this week", "HX-310", "EXPORT", "DELEGATION_SCOPE_DRIFT(F13)", "UsualClients(new)",
                "The agent exports a project outside the delegation", "이 요청 승인", "이상 신고 후 에이전트 정지",
                "/contexa/agent-confirmations/" + asked.confirmationId() + "/approve",
                "/contexa/agent-confirmations/" + asked.confirmationId() + "/report")
                .doesNotContain("confirmationResult");

        service.reject(asked.confirmationId(), "alice", "not this project");
        ExtendedModelMap decided = new ExtendedModelMap();
        pages.confirmation(asked.confirmationId(), alice, new MockHttpServletRequest(), decided);
        String english = render("contexa/agent-confirmation", Locale.ENGLISH, decided);
        assertThat(english).contains("confirmationResult", "Refused", asked.confirmationId(), "not this project")
                .doesNotContain("approveForm");
        assertThatThrownBy(() -> pages.confirmation(asked.confirmationId(), new TestingAuthenticationToken("bob",
                null), new MockHttpServletRequest(), new ExtendedModelMap()))
                .isInstanceOf(ResponseStatusException.class);

        ExtendedModelMap list = new ExtendedModelMap();
        assertThat(pages.list(alice, new MockHttpServletRequest(), list)).isEqualTo("contexa/agent-confirmations");
        assertThat(render("contexa/agent-confirmations", Locale.KOREAN, list)).contains("내 에이전트 요청",
                "report-agent", "거절됨", "/contexa/agent-confirmations/" + asked.confirmationId());
    }

    @Test
    void anApprovedResultShowsItsAuthorizationRecord() {
        AgentConfirmation asked = ask();
        AgentConfirmation approved = service.approve(asked.confirmationId(), "alice", null);
        ExtendedModelMap model = new ExtendedModelMap();
        pages.confirmation(asked.confirmationId(), new TestingAuthenticationToken("alice", null),
                new MockHttpServletRequest(), model);

        assertThat(render("contexa/agent-confirmation", Locale.KOREAN, model)).contains("인가 기록",
                approved.authorizationId(), "승인됨");
    }

    /** AM-4: a release needs the accountable person or an administrator; a kill switch stop needs an administrator. */
    @Test
    @SuppressWarnings("unchecked")
    void theAccountablePersonReleasesTheirOwnStoppedAgentButNotAKillSwitchStop() {
        InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
        registry.register(new AgentRegistrationRequest(null, "sync-agent", "Sync", null, "sync-client", "alice", true));
        registry.register(new AgentRegistrationRequest(null, "kill-agent", "Kill", null, "kill-client", "alice", true));
        registry.suspend(null, "sync-agent", "BLOCK: Bulk export");
        registry.suspend(null, "kill-agent", AgentContainmentService.KILL_SWITCH_REASON + "incident 42");
        InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
        actions.saveAction("alice::agent::report-agent", ZeroTrustAction.BLOCK, Map.of());
        when(records.findTop500ByEventCategoryInOrderByTimestampDesc(any())).thenReturn(List.of(AuditLog.builder()
                .eventCategory("AGENT_STOPPED").subjectKind("DELEGATED_AGENT").delegatorId("alice")
                .agentId("report-agent").reason("Export outside the delegation")
                .timestamp(LocalDateTime.now().minusMinutes(5)).build()));
        AgentContainmentService containment = new AgentContainmentService(actions, registry, null, null, null,
                mock(CentralAuditFacade.class));
        pages.setStops(new AgentContainmentAdminService(containment, registry, records, null));
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        TestingAuthenticationToken alice = new TestingAuthenticationToken("alice", null);

        ExtendedModelMap model = new ExtendedModelMap();
        pages.list(alice, new MockHttpServletRequest(), model);
        assertThat((List<AgentConfirmationController.StoppedAgent>) model.get("stoppedAgents"))
                .extracting(AgentConfirmationController.StoppedAgent::agentId, AgentConfirmationController.StoppedAgent::killSwitch)
                .containsExactlyInAnyOrder(tuple("report-agent", false),
                        tuple("sync-agent", false),
                        tuple("kill-agent", true));
        assertThat(render("contexa/agent-confirmations", Locale.KOREAN, model)).contains("정지된 내 에이전트",
                "/contexa/agent-confirmations/stops/release", "킬 스위치로 정지됨");

        RedirectAttributesModelMap blank = new RedirectAttributesModelMap();
        pages.release("DELEGATED", "report-agent", " ", alice, new MockHttpServletRequest(), blank);
        assertThat(blank.getFlashAttributes()).containsKey("errorMessage");
        RedirectAttributesModelMap byBob = new RedirectAttributesModelMap();
        pages.release("DELEGATED", "report-agent", "trusted", new TestingAuthenticationToken("bob", null),
                new MockHttpServletRequest(), byBob);
        assertThat(byBob.getFlashAttributes()).containsKey("errorMessage");
        assertThat(actions.getCurrentAction("alice::agent::report-agent")).isEqualTo(ZeroTrustAction.BLOCK);

        RedirectAttributesModelMap released = new RedirectAttributesModelMap();
        pages.release("DELEGATED", "report-agent", "trusted again", alice, new MockHttpServletRequest(), released);
        assertThat(released.getFlashAttributes()).containsKey("message");
        assertThat(actions.getCurrentAction("alice::agent::report-agent")).isNotEqualTo(ZeroTrustAction.BLOCK);
        pages.release("AUTONOMOUS", "sync-agent", "reviewed", alice, new MockHttpServletRequest(),
                new RedirectAttributesModelMap());
        assertThat(registry.find(null, "sync-agent")).map(agent -> agent.status()).contains(AgentStatus.ACTIVE);
        RedirectAttributesModelMap kill = new RedirectAttributesModelMap();
        pages.release("AUTONOMOUS", "kill-agent", "reviewed", alice, new MockHttpServletRequest(), kill);
        assertThat(kill.getFlashAttributes()).containsKey("errorMessage");
        assertThat(registry.find(null, "kill-agent")).map(agent -> agent.status()).contains(AgentStatus.SUSPENDED);
    }

    @Test
    void anAgentReadsOnlyItsOwnConfirmationAndMayAskForOne() {
        AgentConfirmationApiController api = new AgentConfirmationApiController(service);
        AgentConfirmation asked = ask();
        MockHttpServletRequest fromAgent = agentRequest("alice", "report-agent");

        assertThat(api.status(asked.confirmationId(), new TestingAuthenticationToken("alice", null), fromAgent)
                .getBody()).satisfies(status -> {
            assertThat(status.status()).isEqualTo("PENDING");
            assertThat(status.refused()).isFalse();
            assertThat(status.authorizationId()).isNull();
        });
        assertThat(api.status(asked.confirmationId(), new TestingAuthenticationToken("alice", null),
                agentRequest("alice", "other-agent")).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        // The person's own request is no agent's.
        assertThat(api.status(asked.confirmationId(), new TestingAuthenticationToken("alice", null),
                new MockHttpServletRequest()).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        AgentConfirmationApiController.ConfirmationStatus requested = api.ask(
                new AgentConfirmationApiController.ConfirmationAsk("post", "/api/exports?format=zip", null,
                        "The weekly export was moved to tonight"),
                new TestingAuthenticationToken("alice", null), fromAgent).getBody();
        assertThat(requested.trigger()).isEqualTo(AgentConfirmation.REQUESTED);
        assertThat(store.find(requested.confirmationId())).map(AgentConfirmation::reason)
                .contains("The weekly export was moved to tonight");
        assertThat(api.ask(new AgentConfirmationApiController.ConfirmationAsk("GET", "api/no-slash", null, null),
                new TestingAuthenticationToken("alice", null), fromAgent).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    /** docs/agent F-2: the agent's own ask is bound in the request's tenant, as the gate binds the request. */
    @Test
    void anAgentsAskIsBoundInTheRequestsTenant() {
        AgentConfirmationApiController api = new AgentConfirmationApiController(service);
        MockHttpServletRequest fromAgent = agentRequest("alice", "report-agent");
        fromAgent.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP, new AuthenticationStamp("alice", null,
                null, true, null, null, null, null, null, null, List.of(), Map.of("tenantId", "tenant-a")));

        AgentConfirmationApiController.ConfirmationStatus requested = api.ask(
                new AgentConfirmationApiController.ConfirmationAsk("POST", "/api/exports?format=zip", null, null),
                new TestingAuthenticationToken("alice", null), fromAgent).getBody();

        assertThat(store.find(requested.confirmationId())).hasValueSatisfying(asked -> {
            assertThat(asked.tenantId()).isEqualTo("tenant-a");
            assertThat(asked.requestHash()).isEqualTo(AgentRequestBinding.hash("tenant-a", "alice", "report-agent",
                    "POST", "/api/exports", "format=zip", null, null));
        });
    }

    private AgentConfirmation ask() {
        return service.request(new AgentConfirmationService.ConfirmationRequest(AGENT, "hash-1", "POST",
                "/api/exports?format=zip", AgentConfirmation.DECISION_CHALLENGE, "Unusual export", "req-1", null))
                .orElseThrow();
    }

    private static MockHttpServletRequest agentRequest(String user, String agent) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, new DelegationStamp(user, agent, true, null,
                null, null, List.of(), List.of(), null, null, null, null, Map.of()));
        return request;
    }

    private String render(String template, Locale locale, ExtendedModelMap model) {
        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext, "GET", "/contexa/agent-confirmations");
        WebContext context = new WebContext(JakartaServletWebApplication.buildApplication(servletContext)
                .buildExchange(request, new MockHttpServletResponse()), locale, model);
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
