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
package io.contexa.contexaiam.admin.web.monitoring.controller;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentDelegationRequest;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import io.contexa.contexaiam.admin.web.agent.dto.AgentView;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.data.domain.PageImpl;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent A5-5: the decision record fields on the console (AM-5, AM-1, AM-2), rendered from the real templates. */
class AgentDecisionRecordTemplateTest {

    private final SpringTemplateEngine engine = engine();

    @Test
    void theMonitorListOffersTheSubjectChipsAndNamesTheAgentOfADecision() {
        AuditLog row = agentDecision();
        Map<String, Object> variables = new HashMap<>(Map.of("logPage", new PageImpl<>(List.of(row)), "hours", 24,
                "subject", "DELEGATED_AGENT", "subjectKinds", SecurityMonitorController.SUBJECT_KINDS,
                "totalCount", 1L, "authSuccess", 0L, "authFailure", 0L, "securityDecision", 1L, "userBlocked", 0L,
                "mfaVerified", 0L));
        variables.put("adminOverride", 0L);
        variables.put("integrity", Map.of(7L, "MISMATCH"));

        String korean = render("contexa/admin/security-monitor", "/contexa/admin/security-monitor", Locale.KOREAN,
                variables);
        assertThat(korean).contains(">사람<", ">위임 에이전트<", ">단독 에이전트<", "report-agent", "기록 무결성", ">불일치<");
        assertThat(render("contexa/admin/security-monitor", "/contexa/admin/security-monitor", Locale.ENGLISH,
                variables)).contains(">Person<", ">Delegated agent<", ">Autonomous agent<");
    }

    @Test
    void theMonitorDetailShowsTheRecordFieldsAndTheDelegationAsRecorded() {
        InMemoryDelegationRegistry delegations = new InMemoryDelegationRegistry();
        AgentDelegation delegation = delegations.record(new AgentDelegationRequest(null, "alice", "report-agent",
                null, "DATA_EXPORT", "Export the HX-310 package", List.of("EXPORT"), List.of("HX-310"), false, null,
                null, Instant.parse("2026-10-24T04:00:00Z"), Instant.parse("2026-10-24T08:00:00Z"), "alice", null));
        AuditLog row = agentDecision();
        row.setDelegationId(delegation.delegationId());
        Map<String, Object> variables = new HashMap<>();
        variables.put("log", row);
        variables.put("delegation", delegation);
        variables.put("integrity", "VERIFIED");

        String html = render("contexa/admin/security-monitor-detail", "/contexa/admin/security-monitor/7",
                Locale.KOREAN, variables);

        assertThat(html).contains("DELEGATION_SCOPE_DRIFT(F13)", "BLOCK", "MODEL_DECISION", "a1b2c3", "report-agent",
                "alice", "Export the HX-310 package", "EXPORT", "HX-310", "판정이 든 위험 사실", "요청 맥락 해시",
                "허용 작업", ">확인됨<");
        variables.put("delegation", null);
        assertThat(render("contexa/admin/security-monitor-detail", "/contexa/admin/security-monitor/7",
                Locale.ENGLISH, variables)).contains("Contexa keeps no record of this delegation here");
        AuditLog person = AuditLog.builder().id(9L).principalName("bob").decision("ALLOW")
                .timestamp(LocalDateTime.of(2026, 10, 24, 5, 0)).build();
        assertThat(render("contexa/admin/security-monitor-detail", "/contexa/admin/security-monitor/9",
                Locale.KOREAN, Map.of("log", person))).doesNotContain("fa-robot");
    }

    @Test
    void theAgentScreensShowTheLatestDecisionAndTheLatestRecords() {
        InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
        registry.register(new AgentRegistrationRequest(null, "report-agent", "Report agent", "report",
                "report-agent-client", "carol", null));
        AgentView agent = AgentView.of(registry.find(null, "report-agent").orElseThrow());

        String list = render("contexa/admin/agents", "/contexa/admin/agents", Locale.KOREAN, Map.of(
                "agents", List.of(agent), "latestDecisions", Map.of("report-agent", "BLOCK"), "currentFilter", "all",
                "provisioningAvailable", false));
        assertThat(list).contains("최근 판단", ">BLOCK<");

        String detail = render("contexa/admin/agent-detail", "/contexa/admin/agents/detail", Locale.KOREAN, Map.of(
                "agent", agent, "learningControllable", false, "learningQuarantined", false, "delegations", List.of(),
                "provisioningAvailable", false, "decisions", List.of(agentDecision())));
        assertThat(detail).contains("최근 판정 기록", "DELEGATION_SCOPE_DRIFT(F13)", "/contexa/admin/security-monitor/7");
        assertThat(render("contexa/admin/agent-detail", "/contexa/admin/agents/detail", Locale.KOREAN, Map.of(
                "agent", agent, "learningControllable", false, "learningQuarantined", false, "delegations", List.of(),
                "provisioningAvailable", false, "decisions", List.of())))
                .contains("이 에이전트의 판정 기록이 아직 없습니다.");
    }

    private static AuditLog agentDecision() {
        return AuditLog.builder()
                .id(7L)
                .timestamp(LocalDateTime.of(2026, 10, 24, 5, 0))
                .principalName("alice")
                .resourceIdentifier("GB-500")
                .decision("BLOCK")
                .eventCategory("SECURITY_DECISION")
                .reason("Export outside the delegation")
                .subjectKind("DELEGATED_AGENT")
                .agentId("report-agent")
                .delegatorId("alice")
                .delegationId("DLG-7")
                .targetAction("EXPORT")
                .riskState("DELEGATION_SCOPE_DRIFT(F13)")
                .enforcementAction("BLOCK")
                .enforcementCause("MODEL_DECISION")
                .requestContextHash("a1b2c3")
                .build();
    }

    private String render(String template, String path, Locale locale, Map<String, Object> variables) {
        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext, "GET", path);
        WebContext context = new WebContext(JakartaServletWebApplication.buildApplication(servletContext)
                .buildExchange(request, new MockHttpServletResponse()), locale, variables);
        return engine.process(template, context);
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
}
