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
package io.contexa.contexacore.autonomous.agent;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * docs/agent A5-4: a risky decision on an agent's request narrows its later requests to reading for a period; a
 * request outside the narrowed scope is refused; a later narrowing never widens it; the narrowing is an SPI.
 */
class AgentScopeServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-24T03:00:00Z");
    private static final ZeroTrustSubject AGENT = new ZeroTrustSubject(null, "alice", SubjectKind.DELEGATED_AGENT,
            "report-agent", null);

    private final AgentConfirmationServiceTest.MovingClock clock = new AgentConfirmationServiceTest.MovingClock(NOW);
    private final InMemoryAgentScopeStore store = new InMemoryAgentScopeStore();
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final AgentScopeService service = new AgentScopeService(store,
            new ReadOnlyAgentScopeNarrower(Duration.ofHours(1), 0.7), audit, clock);

    @Test
    void aRiskyDecisionNarrowsTheAgentToReadingForThePeriod() {
        assertThat(service.onDecision(agentEvent(), decision("CHALLENGE", 0.6)))
                .hasValueSatisfying(step -> assertThat(step).startsWith("SCOPE_NARROWED(READ until"));

        assertThat(service.refusing(AGENT, "GET", "/api/projects/HX-310/documents")).isEmpty();
        assertThat(service.refusing(AGENT, "POST", "/api/projects/HX-310/documents")).isPresent();
        assertThat(service.refusing(AGENT, "GET", "/api/projects/HX-310/export")).isPresent();
        assertThat(service.refusing(AGENT, "DELETE", "/api/projects/HX-310")).isPresent();
        // Another agent of the person and the person are not narrowed.
        assertThat(service.refusing(new ZeroTrustSubject(null, "alice", SubjectKind.DELEGATED_AGENT, "other-agent",
                null), "POST", "/api/projects")).isEmpty();
        assertThat(service.refusing(ZeroTrustSubject.person("alice"), "POST", "/api/projects")).isEmpty();
        ArgumentCaptor<AuditRecord> record = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordSync(record.capture());
        assertThat(record.getValue().getEventCategory()).isEqualTo(AuditEventCategory.AGENT_SCOPE_NARROWED);
        assertThat(record.getValue().getDelegatorId()).isEqualTo("alice");

        clock.advance(Duration.ofMinutes(61));
        assertThat(service.refusing(AGENT, "POST", "/api/projects/HX-310/documents")).isEmpty();
        assertThat(service.inForce()).isEmpty();
    }

    @Test
    void aCalmDecisionOrAPersonsDecisionNarrowsNothing() {
        assertThat(service.onDecision(agentEvent(), decision("ALLOW", 0.2))).isEmpty();
        assertThat(service.onDecision(SecurityEvent.builder().userId("alice").build(), decision("BLOCK", 0.9)))
                .isEmpty();
        assertThat(store.find("alice::agent::report-agent")).isEmpty();

        assertThat(service.onDecision(agentEvent(), decision("ALLOW", 0.75))).isPresent();
    }

    @Test
    void aLaterNarrowingNeverWidensTheScopeAndKeepsTheLaterEnd() {
        AgentScopeService wide = new AgentScopeService(store, (subject, event, result) -> Optional.of(
                new AgentScopeNarrower.Narrowing(EnumSet.of(ActionFamily.READ, ActionFamily.WRITE, ActionFamily.EXPORT),
                        Duration.ofHours(3), "a wide narrowing")), audit, clock);
        service.onDecision(agentEvent(), decision("BLOCK", 0.95));

        wide.onDecision(agentEvent(), decision("ALLOW", 0.1));

        AgentScopeRestriction kept = service.inForce(AGENT).orElseThrow();
        assertThat(kept.allowed()).containsExactly(ActionFamily.READ);
        assertThat(kept.until()).isEqualTo(NOW.plus(Duration.ofHours(3)));
        assertThat(kept.narrowedAt()).isEqualTo(NOW);
        assertThat(service.refusing(AGENT, "POST", "/api/projects")).isPresent();
    }

    @Test
    void anApplicationsOwnNarrowingIsUsed() {
        // Only the exports are taken from the agent, for ten minutes, after any decision.
        AgentScopeService own = new AgentScopeService(store, (subject, event, result) -> Optional.of(
                new AgentScopeNarrower.Narrowing(EnumSet.of(ActionFamily.READ, ActionFamily.WRITE),
                        Duration.ofMinutes(10), "no exports for a while")), null, clock);

        own.onDecision(agentEvent(), decision("ALLOW", 0.1));

        assertThat(own.refusing(AGENT, "POST", "/api/projects/HX-310/documents")).isEmpty();
        assertThat(own.refusing(AGENT, "GET", "/api/projects/HX-310/export")).isPresent();
        clock.advance(Duration.ofMinutes(11));
        assertThat(own.refusing(AGENT, "GET", "/api/projects/HX-310/export")).isEmpty();
    }

    /** The words of a path may name a graver operation than its method, never a lighter one. */
    @Test
    void theWordsOfAPathNeverMakeAWritingMethodARead() {
        service.onDecision(agentEvent(), decision("CHALLENGE", 0.6));

        assertThat(service.refusing(AGENT, "DELETE", "/api/lists/7")).isPresent();
        assertThat(service.refusing(AGENT, "POST", "/api/search/x")).isPresent();
        assertThat(service.refusing(AGENT, "PUT", "/api/views/7")).isPresent();
        assertThat(service.refusing(AGENT, "PATCH", "/api/downloads/7")).isPresent();
        assertThat(service.refusing(AGENT, "POST", "/api/documents;list=1")).isPresent();
        assertThat(service.refusing(AGENT, "PROPFIND", "/api/lists/7")).as("a method that says nothing").isPresent();
        assertThat(AgentScopeService.operation("DELETE", "/api/lists/7")).isEqualTo(ActionFamily.DELETE);
        assertThat(AgentScopeService.operation("POST", "/api/search/x")).isEqualTo(ActionFamily.WRITE);
        assertThat(AgentScopeService.operation("DELETE", "/api/update/7")).isEqualTo(ActionFamily.DELETE);

        // A read stays a read, and a word still raises what the method says.
        assertThat(service.refusing(AGENT, "GET", "/api/lists/7")).isEmpty();
        assertThat(service.refusing(AGENT, "HEAD", "/api/search/x")).isEmpty();
        assertThat(service.refusing(AGENT, "OPTIONS", "/api/projects")).isEmpty();
        assertThat(AgentScopeService.operation("GET", "/api/exports")).isEqualTo(ActionFamily.EXPORT);
        assertThat(AgentScopeService.operation("POST", "/api/exports")).isEqualTo(ActionFamily.EXPORT);
        assertThat(AgentScopeService.operation("POST", "/api/run/job")).isEqualTo(ActionFamily.EXECUTE);
        assertThat(AgentScopeService.operation("POST", "/api/projects")).isEqualTo(ActionFamily.WRITE);
        assertThat(AgentScopeService.operation(null, "/api/lists")).as("no method named").isEqualTo(ActionFamily.READ);
    }

    /** What routing serves is what is read: an encoded word is its word, a path parameter is no word of the path. */
    @Test
    void aPathIsReadAsTheRoutingOfTheApplicationReadsIt() {
        service.onDecision(agentEvent(), decision("CHALLENGE", 0.6));

        assertThat(service.refusing(AGENT, "GET", "/api/%65xport/x")).isPresent();
        assertThat(service.refusing(AGENT, "GET", "/api/EXP%4FRT/x")).isPresent();
        assertThat(service.refusing(AGENT, "GET", "/api/exp%6Frts;v=1/x")).isPresent();
        assertThat(AgentScopeService.operation("GET", "/api/%65xport/x")).isEqualTo(ActionFamily.EXPORT);
        assertThat(AgentScopeService.operation("GET", "/api/documents;export=1")).isEqualTo(ActionFamily.READ);
        // Braces in a request are not a template's: what stands between them is read.
        assertThat(AgentScopeService.operation("GET", "/api/%7B/export/%7D/x")).isEqualTo(ActionFamily.EXPORT);
        // A path no router can read names no operation.
        assertThat(service.refusing(AGENT, "GET", "/api/%zz")).isPresent();
        assertThat(AgentScopeService.operation("GET", "/api/%zz")).isEqualTo(ActionFamily.UNKNOWN);
    }

    @Test
    void anAccountsDeletionForgetsWhatAgentsDidForThePerson() {
        service.onDecision(agentEvent(), decision("CHALLENGE", 0.6));
        InMemoryAgentConfirmationStore confirmations = new InMemoryAgentConfirmationStore();
        confirmations.save(new AgentConfirmation("c-1", null, "DELEGATED_AGENT", "alice", "report-agent", null,
                "alice", "hash", "POST", "/api/exports", AgentConfirmation.DECISION_CHALLENGE, null, null,
                AgentConfirmation.Status.PENDING, NOW, NOW.plusSeconds(900), null, null, null, null, null));
        InMemoryAgentNoticeStore notices = new InMemoryAgentNoticeStore();
        notices.save(new AgentNotice("n-1", AgentNotice.AGENT_STOPPED, null, "alice", "report-agent", null, "s", "m",
                null, null, NOW, AgentNotice.CONSOLE, null));
        notices.save(new AgentNotice("n-2", AgentNotice.AGENT_STOPPED, null, "bob", "report-agent", null, "s", "m",
                null, null, NOW, AgentNotice.CONSOLE, null));

        new AgentRequestStatePurgeContributor(store, confirmations, notices).purge("alice");

        assertThat(store.find("alice::agent::report-agent")).isEmpty();
        assertThat(confirmations.find("c-1")).isEmpty();
        assertThat(notices.list(null, 10)).extracting(AgentNotice::noticeId).containsExactly("n-2");
    }

    private static SecurityEvent agentEvent() {
        SecurityEvent event = SecurityEvent.builder().userId("alice").build();
        event.addMetadata("executionSubjectKind", "DELEGATED_AGENT");
        event.addMetadata("agentId", "report-agent");
        event.addMetadata("requestId", "req-7");
        return event;
    }

    private static ProcessingResult decision(String action, double risk) {
        return ProcessingResult.builder().success(true).action(action).riskScore(risk).build();
    }
}
