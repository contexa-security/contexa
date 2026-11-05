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
package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.event.publisher.CanonicalExecutionEventMetadataSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent A5-1: whose decision a request reads and writes. */
class ZeroTrustSubjectTest {

    @AfterEach
    void leaveTheRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void q17_aConsoleSessionIsKeptApartFromThePersonOfItsName() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/admin/users");
        ConsoleSession.mark(request);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        ZeroTrustSubject subject = ZeroTrustSubject.of("rcboss", (DelegationStamp) null);

        assertThat(subject.console()).isTrue();
        assertThat(subject.storageKey()).isEqualTo("console::rcboss");
    }

    @Test
    void q17_aRequestOfTheApplicationIsThePersons() {
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(new MockHttpServletRequest("GET", "/contexa/admin/users")));

        assertThat(ZeroTrustSubject.of("rcboss", (DelegationStamp) null).storageKey()).isEqualTo("rcboss");
    }

    @Test
    void q17_anEventOfTheConsoleNamesItsSubject() {
        Map<String, Object> facts = CanonicalExecutionEventMetadataSupport.enrich(Map.of("consoleSession", true));

        assertThat(facts.get("executionSubjectKind")).isEqualTo("CONSOLE_ADMIN");
        assertThat(ZeroTrustSubject.ofFacts("rcboss", facts).storageKey()).isEqualTo("console::rcboss");
    }

    @Test
    void q17_whatAConsoleSessionDecidesIsWrittenUnderItsOwnKey() {
        assertThat(ZeroTrustSubject.of(event("rcboss", Map.of("executionSubjectKind", "CONSOLE_ADMIN"))).storageKey())
                .isEqualTo("console::rcboss");
        assertThat(ZeroTrustSubject.ofFacts("rcboss", Map.of("executionSubjectKind", "CONSOLE_ADMIN")).storageKey())
                .isEqualTo("console::rcboss");
    }

    @Test
    void aPersonAServiceClientAndAnAgentOnItsOwnKeepTheirUserId() {
        assertThat(ZeroTrustSubject.of("alice", (DelegationStamp) null).storageKey()).isEqualTo("alice");
        assertThat(ZeroTrustSubject.of(event("alice", Map.of("executionSubjectKind", "HUMAN_USER"))).storageKey())
                .isEqualTo("alice");
        assertThat(ZeroTrustSubject.of(event("batch-client", Map.of("executionSubjectKind", "SERVICE_CLIENT")))
                .storageKey()).isEqualTo("batch-client");
        ZeroTrustSubject alone = ZeroTrustSubject.of("report-client", stamp(false, "report-agent", null));
        assertThat(alone.kind()).isEqualTo(SubjectKind.AUTONOMOUS_AGENT);
        assertThat(alone.storageKey()).isEqualTo("report-client");
        assertThat(ZeroTrustSubject.of(event("report-client", Map.of("executionSubjectKind", "AUTONOMOUS_AGENT",
                "agentId", "report-agent"))).storageKey()).isEqualTo("report-client");
    }

    @Test
    void anAgentActingForAPersonIsKeyedApartFromThePersonTheSameWayOnTheRequestAndOnTheEvent() {
        ZeroTrustSubject onRequest = ZeroTrustSubject.of("alice", stamp(true, "report-agent", "DLG-7"));
        ZeroTrustSubject onEvent = ZeroTrustSubject.of(event("alice", Map.of("executionSubjectKind", "DELEGATED_AGENT",
                "agentId", "report-agent", "delegationId", "DLG-7", "tenantId", "t-1")));

        assertThat(onRequest.delegatedAgent()).isTrue();
        assertThat(onRequest.storageKey()).isEqualTo("alice::agent::report-agent");
        assertThat(onEvent.storageKey()).isEqualTo(onRequest.storageKey());
        assertThat(onEvent.delegationId()).isEqualTo("DLG-7");
        assertThat(onEvent.tenantId()).isEqualTo("t-1");
        // An authorization event's payload names the subject the same way.
        assertThat(ZeroTrustSubject.ofFacts("alice", Map.of("executionSubjectKind", "DELEGATED_AGENT",
                "agentId", "report-agent")).storageKey()).isEqualTo(onRequest.storageKey());
        assertThat(ZeroTrustSubject.ofFacts("alice", Map.of("executionSubjectKind", "HUMAN_USER",
                "agentId", "report-agent")).storageKey()).as("a person's request names no agent").isEqualTo("alice");
        // The delegation is not keyed: a token that names none reads the same decisions.
        assertThat(ZeroTrustSubject.of("alice", stamp(true, "report-agent", null)).storageKey())
                .isEqualTo(onRequest.storageKey());
    }

    @Test
    void aDelegationThatNamesNoAgentAndNoUserAreNoAgentKey() {
        assertThat(ZeroTrustSubject.of("alice", stamp(true, null, "DLG-7")).storageKey()).isEqualTo("alice");
        assertThat(ZeroTrustSubject.of(" ", (DelegationStamp) null)).isNull();
        assertThat(ZeroTrustSubject.of((SecurityEvent) null)).isNull();
    }

    @Test
    void aPersonNamedAsTheConsolesKeyIsNotTheConsole() {
        String console = consoleKeyOf("admin");
        RequestContextHolder.resetRequestAttributes();

        assertThat(ZeroTrustSubject.person("console::admin").storageKey()).isNotEqualTo(console);
        assertThat(ZeroTrustSubject.of("CONSOLE::ADMIN", (DelegationStamp) null).storageKey())
                .isEqualTo(ZeroTrustSubject.person("console::admin").storageKey());
        assertThat(ZeroTrustSubject.of(event("console::admin", Map.of("executionSubjectKind", "HUMAN_USER")))
                .storageKey()).isNotEqualTo(console);
        assertThat(ZeroTrustSubject.ofFacts(" console::admin ", Map.of()).storageKey()).isNotEqualTo(console);
    }

    @Test
    void aPersonNamedAsAnAgentsKeyIsNotTheAgent() {
        String agent = ZeroTrustSubject.of("alice", stamp(true, "report-agent", null)).storageKey();

        assertThat(ZeroTrustSubject.person("alice::agent::report-agent").storageKey()).isNotEqualTo(agent);
        assertThat(ZeroTrustSubject.of(event("alice::agent::report-agent", Map.of("executionSubjectKind", "HUMAN_USER")))
                .storageKey()).isNotEqualTo(agent);
    }

    @Test
    void aServiceClientAndAnAgentOnItsOwnAreKeptOffTheInternalKeysAsAPersonIs() {
        assertThat(ZeroTrustSubject.of(event("console::batch", Map.of("executionSubjectKind", "SERVICE_CLIENT")))
                .storageKey()).doesNotStartWith("console::");
        assertThat(ZeroTrustSubject.of("alice::agent::x", stamp(false, "report-agent", null)).storageKey())
                .doesNotContain("::agent::");
    }

    @Test
    void anAdministratorAndAnAgentAreKeptApartWhateverTheyAreNamed() {
        String console = consoleKeyOf("agent::bot");
        RequestContextHolder.resetRequestAttributes();

        assertThat(ZeroTrustSubject.of("console", stamp(true, "bot", null)).storageKey()).isEqualTo("console::agent::bot");
        assertThat(console).isNotEqualTo("console::agent::bot");
    }

    @Test
    void theAgentOfAPersonNamedAsAKeyIsNoAgentOfAnotherPerson() {
        String agent = ZeroTrustSubject.of("alice::agent::x", stamp(true, "bot", null)).storageKey();

        assertThat(agent).isNotEqualTo(ZeroTrustSubject.of("alice", stamp(true, "x::agent::bot", null)).storageKey());
        assertThat(agent).doesNotStartWith("alice::agent::");
    }

    @Test
    void anOrdinaryNameKeepsTheKeysItHad() {
        assertThat(ZeroTrustSubject.of("alice", stamp(true, "report-agent", null)).storageKey())
                .isEqualTo("alice::agent::report-agent");
        assertThat(consoleKeyOf("rcboss")).isEqualTo("console::rcboss");
        RequestContextHolder.resetRequestAttributes();
        assertThat(ZeroTrustSubject.person("alice").storageKey()).isEqualTo("alice");
    }

    @Test
    void anAgentReadsTheBlockOfThePersonItActsForAndNotTheConsolesOfThatForm() {
        InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
        actions.saveAction(consoleKeyOf("admin"), ZeroTrustAction.BLOCK, Map.of());
        RequestContextHolder.resetRequestAttributes();
        ZeroTrustSubject agent = ZeroTrustSubject.of("console::admin", stamp(true, "report-agent", null));

        assertThat(agent.currentAction(actions)).isNotEqualTo(ZeroTrustAction.BLOCK);

        actions.saveAction(ZeroTrustSubject.person("console::admin").storageKey(), ZeroTrustAction.BLOCK, Map.of());

        assertThat(agent.currentAction(actions)).isEqualTo(ZeroTrustAction.BLOCK);
    }

    private static String consoleKeyOf(String userId) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/admin/users");
        ConsoleSession.mark(request);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        return ZeroTrustSubject.of(userId, (DelegationStamp) null).storageKey();
    }

    private static DelegationStamp stamp(boolean delegated, String agentId, String delegationId) {
        return new DelegationStamp("alice", agentId, delegated, null, null, null, List.of(), List.of(), null, null,
                null, Instant.parse("2026-10-24T12:00:00Z"),
                delegationId != null ? Map.of("delegationId", delegationId) : Map.of());
    }

    private static SecurityEvent event(String userId, Map<String, Object> metadata) {
        SecurityEvent event = new SecurityEvent();
        event.setUserId(userId);
        event.setMetadata(new HashMap<>(metadata));
        return event;
    }
}
