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

import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentRegistration;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexaiam.admin.web.agent.dto.AgentView;
import io.contexa.contexaiam.admin.web.agent.service.AgentProvisioning;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent A3-8: the agent screen draws its learning section from the real template and messages: the state, the
 * delegation and reason fields and the three actions, or why there is nothing to control. The shared page fragments
 * (head, header, menu, footer) are drawn as stand-ins, since they need the signed-in administrator.
 */
class AgentDetailTemplateTest {

    private final SpringTemplateEngine engine = engine();
    private final AgentView agent = agent();
    private List<AgentDelegationViews.DelegationView> delegations = List.of();

    @Test
    void theLearningSectionOffersTheActionsWithTheAgentAndTheState() {
        String html = render(Locale.KOREAN, true, true);

        assertThat(html).contains("action=\"/contexa/admin/agents/learning\"", "id=\"learningForm\"",
                "name=\"agentId\" value=\"agent-7\"", "name=\"delegationId\"", "name=\"reason\"",
                "value=\"quarantine\"", "value=\"release\"", "value=\"remove\"",
                "data-confirm=\"이 에이전트가 학습한 것을 지울까요? 되돌릴 수 없습니다.\"",
                ">학습<", ">격리됨<", ">격리<", ">격리 해제<", ">지우기<", "위임 ID(선택)");
        assertThat(html).doesNotContain("??");
        assertThat(render(Locale.KOREAN, true, false)).contains(">사용 중<").doesNotContain(">격리됨<");
        assertThat(render(Locale.ENGLISH, true, false)).contains(">Learning<", ">Quarantine<",
                ">Release quarantine<", ">Remove<", ">In use<").doesNotContain("??");
    }

    /** docs/agent OC-1: the delegations section lists each delegation and offers a revocation for one in force. */
    @Test
    void theDelegationsSectionListsTheDelegationsAndRevokesOneInForce() {
        Instant now = Instant.parse("2026-10-23T05:00:00Z");
        AgentDelegation valid = new AgentDelegation("dlg-1", null, "carol", "agent-7", null, "REPORTING",
                "Weekly HX-310 report", List.of("READ"), List.of("HX-310"), false, null, null,
                now.minusSeconds(3600), now.plusSeconds(3600), null, null, null, "carol", now.minusSeconds(3600));
        AgentDelegation revoked = new AgentDelegation("dlg-2", null, "dave", "agent-7", null, null, null, List.of(),
                List.of(), false, null, null, now.minusSeconds(7200), now.plusSeconds(3600), now.minusSeconds(60),
                "admin-1", "hijacked", "dave", now.minusSeconds(7200));
        AgentDelegation limited = new AgentDelegation("dlg-3", null, "erin", "agent-7", null, "REPORTING",
                "Capped export", List.of("EXPORT"), List.of("HX-310"), false, null, null, now.minusSeconds(60),
                now.plusSeconds(3600), null, null, null, "erin", now.minusSeconds(60), 40, 1200);
        delegations = List.of(AgentDelegationViews.DelegationView.of(valid, now),
                AgentDelegationViews.DelegationView.of(revoked, now), AgentDelegationViews.DelegationView.of(limited, now));

        String html = render(Locale.KOREAN, true, false);

        assertThat(html).contains(">위임<", ">carol<", "Weekly HX-310 report", ">유효<", ">철회됨<",
                "action=\"/contexa/admin/agents/delegations/revoke\"", "name=\"delegationId\" value=\"dlg-1\"")
                .doesNotContain("value=\"dlg-2\"").doesNotContain("??");
        // RL-6: the quantity limits of a delegation, per request and in the session; none reads as a dash.
        assertThat(html).contains(">수량 한도(요청당 / 세션 합계)<", ">40 / 1200<", ">- / -<".replace("- / -", "-"));
        delegations = List.of();
        assertThat(render(Locale.KOREAN, true, false)).contains("아직 이 에이전트에게 일을 맡긴 사람이 없습니다.");
    }

    /** docs/agent OC-3: the registration form, the page that shows the secrets once and the agent's management. */
    @Test
    void theRegistrationPagesAndTheManagementSectionRender() {
        String form = renderPage("contexa/admin/agent-register", Map.of("provisioningAvailable", true));
        assertThat(form).contains("action=\"/contexa/admin/agents/register\"", "name=\"agentId\"", "name=\"sponsorId\"",
                "name=\"ownToken\"", "name=\"actsForPeople\"", ">에이전트 등록<").doesNotContain("??");
        assertThat(renderPage("contexa/admin/agent-register", Map.of("provisioningAvailable", false)))
                .doesNotContain("id=\"agentRegisterForm\"");

        AgentProvisioning.Credentials credentials = new AgentProvisioning.Credentials(registration(), "agent-7-client",
                "s3cret-value", "agent-7", "Ag7!password");
        String shown = renderPage("contexa/admin/agent-credentials", Map.of("credentials", credentials,
                "agent", agent));
        assertThat(shown).contains("agent-7-client", "s3cret-value", "Ag7!password", "한 번만").doesNotContain("??");

        String detail = render(Locale.KOREAN, true, false, true);
        assertThat(detail).contains("action=\"/contexa/admin/agents/manage/sponsor\"",
                "action=\"/contexa/admin/agents/manage/deregister\"", "action=\"/contexa/admin/agents/manage/remove\"",
                ">관리<").doesNotContain("??");
        assertThat(render(Locale.KOREAN, true, false, false)).doesNotContain("id=\"agentManage\"");
    }

    @Test
    void withoutTheAutonomousSecurityPlaneTheSectionSaysWhyAndOffersNoAction() {
        String html = render(Locale.KOREAN, false, false);

        assertThat(html).contains("자율 보안 기능이 꺼져 있어 관리할 학습이 없습니다.")
                .doesNotContain("id=\"learningForm\"").doesNotContain("value=\"remove\"").doesNotContain("??");
    }

    private String render(Locale locale, boolean controllable, boolean quarantined) {
        return render(locale, controllable, quarantined, false);
    }

    private String renderPage(String template, Map<String, Object> variables) {
        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext, "GET", "/contexa/admin/agents");
        WebContext context = new WebContext(JakartaServletWebApplication.buildApplication(servletContext)
                .buildExchange(request, new MockHttpServletResponse()), Locale.KOREAN, variables);
        return engine.process(template, context);
    }

    private String render(Locale locale, boolean controllable, boolean quarantined, boolean provisioning) {
        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext, "GET",
                "/contexa/admin/agents/detail");
        WebContext context = new WebContext(JakartaServletWebApplication.buildApplication(servletContext)
                .buildExchange(request, new MockHttpServletResponse()), locale,
                Map.of("agent", agent, "learningControllable", controllable, "learningQuarantined", quarantined,
                        "delegations", delegations, "provisioningAvailable", provisioning));
        return engine.process("contexa/admin/agent-detail", context);
    }

    private static SpringTemplateEngine engine() {
        ClassLoaderTemplateResolver fragments = resolver("test-templates/", 1);
        fragments.setResolvablePatterns(Set.of("contexa/fragments/*"));
        ClassLoaderTemplateResolver templates = resolver("templates/", 2);
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setFallbackToSystemLocale(false);
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolvers(Set.of(fragments, templates));
        engine.setTemplateEngineMessageSource(messages);
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

    private static AgentRegistration registration() {
        InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
        registry.register(new AgentRegistrationRequest(null, "agent-7", "Report assistant", "report-blueprint",
                "agent-7-client", "carol", null));
        return registry.find(null, "agent-7").orElseThrow();
    }

    private static AgentView agent() {
        InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
        registry.register(new AgentRegistrationRequest(null, "agent-7", "Report assistant", "report-blueprint",
                null, "carol", null));
        return AgentView.of(registry.find(null, "agent-7").orElseThrow());
    }
}
