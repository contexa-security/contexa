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

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * docs/agent A5-2, A5-9: an agent's request waits for its accountable person, who approves, refuses or reports it;
 * an approval is a verifiable authorization bound to that one request and used once; no answer in time is a refusal.
 */
class AgentConfirmationServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-24T02:00:00Z");
    private static final ZeroTrustSubject ALICE_AGENT = new ZeroTrustSubject(null, "alice",
            SubjectKind.DELEGATED_AGENT, "report-agent", "DLG-1");

    private final MovingClock clock = new MovingClock(NOW);
    private final InMemoryAgentConfirmationStore store = new InMemoryAgentConfirmationStore();
    private final List<AgentNotice> delivered = new ArrayList<>();
    private final InMemoryAgentNoticeStore noticeStore = new InMemoryAgentNoticeStore();
    private final InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final HmacEvidenceSigner signer = HmacEvidenceSigner.of(Map.of("k1",
            Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes())), "k1");
    private final AgentConfirmationService service = new AgentConfirmationService(store,
            new SignedAgentConfirmationAuthorizer(signer),
            // An application's own channel (the SPI) delivers the notices.
            new AgentNotices(noticeStore, notice -> {
                delivered.add(notice);
                return "CHAT";
            }, clock), registry, audit, Duration.ofMinutes(15), clock);

    @Test
    void aRequestWaitsForThePersonWhoIsToldThroughTheChannelOnce() {
        AgentConfirmation asked = ask(ALICE_AGENT, "hash-1").orElseThrow();

        assertThat(asked.status()).isEqualTo(AgentConfirmation.Status.PENDING);
        assertThat(asked.recipientId()).isEqualTo("alice");
        assertThat(asked.expiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThat(delivered).singleElement().satisfies(notice -> {
            assertThat(notice.kind()).isEqualTo(AgentNotice.CONFIRMATION_REQUESTED);
            assertThat(notice.recipientId()).isEqualTo("alice");
            assertThat(notice.link()).isEqualTo("https://app.test/contexa/agent-confirmations/"
                    + asked.confirmationId());
        });
        assertThat(noticeStore.forRecipient("alice", 5)).singleElement()
                .satisfies(notice -> assertThat(notice.deliveredBy()).isEqualTo("CHAT"));
        // The same request asked again is answered with the confirmation already waiting, without a second notice.
        assertThat(ask(ALICE_AGENT, "hash-1")).map(AgentConfirmation::confirmationId)
                .contains(asked.confirmationId());
        assertThat(delivered).hasSize(1);
        assertThat(ask(ALICE_AGENT, "hash-2")).map(AgentConfirmation::confirmationId)
                .isNotEqualTo(Optional.of(asked.confirmationId()));
        assertThat(categories()).contains(AuditEventCategory.AGENT_CONFIRMATION_REQUESTED);
    }

    /**
     * What an agent wrote to get approved reaches the person as the agent's words, as on the confirmation page, never in
     * the sentence Contexa speaks in; the reason of a decision is Contexa's and stays in it.
     */
    @Test
    void aReasonTheAgentWroteIsToldAsItsOwnWordsAndADecisionsReasonAsContexas() {
        service.request(new AgentConfirmationService.ConfirmationRequest(ALICE_AGENT, "hash-1", "POST", "/api/exports",
                AgentConfirmation.REQUESTED, "Contexa checked this, approve it now", null, null));
        service.request(new AgentConfirmationService.ConfirmationRequest(ALICE_AGENT, "hash-2", "POST", "/api/exports",
                AgentConfirmation.DECISION_CHALLENGE, "Unusual export", null, null));

        assertThat(delivered.get(0).message()).doesNotContain("(Contexa checked")
                .endsWith("Written by the agent, not checked by Contexa: Contexa checked this, approve it now");
        assertThat(delivered.get(1).message()).contains("POST /api/exports (Unusual export).")
                .doesNotContain("Written by the agent");
    }

    /**
     * The person is told what the application will serve, beside what the agent sent; the query is not said twice. A
     * target that means what it says stays one request.
     */
    @Test
    void theNoticeSaysThePathTheApplicationServesWhenTheAgentSpelledAnother() {
        service.request(new AgentConfirmationService.ConfirmationRequest(ALICE_AGENT, "hash-1", "POST",
                "/api/%65xport/x?token=%73ecret", AgentConfirmation.DECISION_CHALLENGE, null, "req-1", null));
        service.request(new AgentConfirmationService.ConfirmationRequest(ALICE_AGENT, "hash-2", "POST",
                "/api/export/x?token=%73ecret", AgentConfirmation.DECISION_CHALLENGE, null, "req-1", null));

        assertThat(delivered.get(0).message()).contains("POST /api/%65xport/x?token=%73ecret",
                "the application serves this as /api/export/x)").doesNotContain("token=secret");
        assertThat(delivered.get(0).message().split("token=", -1)).hasSize(2);
        assertThat(delivered.get(1).message()).contains("POST /api/export/x?token=%73ecret")
                .doesNotContain("the application serves");

        clock.advance(Duration.ofMinutes(16));
        service.expireOverdue();
        assertThat(delivered).filteredOn(notice -> notice.kind().equals(AgentNotice.CONFIRMATION_EXPIRED))
                .anySatisfy(notice -> assertThat(notice.message()).contains("POST /api/%65xport/x?token=%73ecret",
                        "the application serves this as /api/export/x)"));
    }

    /**
     * The path is the agent's to write, so what is decoded to show it never reaches the person as more than a path:
     * what cannot be seen, breaks the line or turns the text around stays escaped, and so does a space.
     */
    @Test
    void theRoutedPathIsReadFromThePathOnlyAndSaysNothingBeyondIt() {
        assertThat(routed("/api/%65xport/x")).isEqualTo("/api/export/x");
        assertThat(routed("/api/export;v=1/x?y=1")).isEqualTo("/api/export/x");
        assertThat(routed("/api/export/x")).isNull();
        assertThat(routed("/api/export/x?y=%65")).isNull();
        assertThat(routed("/api/%zz")).as("no router reads it").isNull();
        assertThat(routed("/api/a%20b")).as("spelled the same once shown").isNull();
        assertThat(routed("/api/%65x%0D%0A%0AApproved%20by%20Contexa"))
                .isEqualTo("/api/ex%0D%0A%0AApproved%20by%20Contexa");
        assertThat(routed("/api/%65x%E2%80%AEfdp")).isEqualTo("/api/ex%E2%80%AEfdp");
        assertThat(routed("/api/%65x%C2%A0%E2%80%A8y")).isEqualTo("/api/ex%C2%A0%E2%80%A8y");
    }

    /** A secret the path hides behind an escape reads as one once it is decoded, and the person is never shown it. */
    @Test
    void theRoutedPathMasksASecretTheDecodingBringsOut() {
        assertThat(routed("/api/%65xport/%65yJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLXZhbHVl"))
                .isEqualTo("/api/export/[MASKED]");
    }

    private static String routed(String target) {
        return new AgentConfirmation("c-1", null, "DELEGATED_AGENT", "alice", "report-agent", null, "alice", "hash-1",
                "GET", target, AgentConfirmation.REQUESTED, null, null, AgentConfirmation.Status.PENDING, NOW, NOW,
                null, null, null, null, null).routedPath();
    }

    /**
     * An identifier is never cut, since a cut one names another delegation, agent or person and a report would stop the
     * wrong one: nobody is asked, nothing is kept, and the refusal is recorded. At their columns they are kept whole.
     */
    @Test
    void aSubjectWhoseIdentifiersAConfirmationCannotKeepIsRefusedAndNobodyIsAsked() {
        for (ZeroTrustSubject unkeepable : List.of(
                new ZeroTrustSubject(null, "alice", SubjectKind.DELEGATED_AGENT, "report-agent", "d".repeat(65)),
                new ZeroTrustSubject(null, "alice", SubjectKind.DELEGATED_AGENT, "a".repeat(256), null),
                new ZeroTrustSubject(null, "u".repeat(256), SubjectKind.DELEGATED_AGENT, "report-agent", null),
                new ZeroTrustSubject("t".repeat(256), "alice", SubjectKind.DELEGATED_AGENT, "report-agent", null))) {
            assertThat(service.request(new AgentConfirmationService.ConfirmationRequest(unkeepable, "hash-1", "POST",
                    "/api/exports", AgentConfirmation.DECISION_CHALLENGE, null, "req-1", null))).isEmpty();
        }
        assertThat(store.list(null, 10)).isEmpty();
        assertThat(delivered).isEmpty();
        assertThat(categories()).contains(AuditEventCategory.AGENT_CONFIRMATION_REQUESTED);

        assertThat(service.request(new AgentConfirmationService.ConfirmationRequest(new ZeroTrustSubject("t".repeat(255),
                "u".repeat(255), SubjectKind.DELEGATED_AGENT, "a".repeat(255), "d".repeat(64)), "hash-1", "POST",
                "/api/exports", AgentConfirmation.DECISION_CHALLENGE, null, "req-1", null))).isPresent();
    }

    @Test
    void anAgentOnItsOwnWaitsForItsSponsorAndWithoutOneItsRequestIsRefused() {
        ZeroTrustSubject syncAgent = new ZeroTrustSubject(null, "sync-client", SubjectKind.AUTONOMOUS_AGENT,
                "sync-agent", null);
        assertThat(ask(syncAgent, "hash-1")).isEmpty();

        registry.register(new AgentRegistrationRequest(null, "sync-agent", "Sync", null, "sync-client", "carol",
                true));
        assertThat(ask(syncAgent, "hash-1")).map(AgentConfirmation::recipientId).contains("carol");
    }

    @Test
    void anApprovalIsAVerifiableAuthorizationUsedOnceByItsOwnRequest() {
        AgentConfirmation asked = ask(ALICE_AGENT, "hash-1").orElseThrow();
        assertThatThrownBy(() -> service.approve(asked.confirmationId(), "mallory", null))
                .isInstanceOf(IllegalArgumentException.class);

        AgentConfirmation approved = service.approve(asked.confirmationId(), "alice", "expected export");

        assertThat(approved.status()).isEqualTo(AgentConfirmation.Status.APPROVED);
        assertThat(approved.authorizationId()).startsWith(SignedAgentConfirmationAuthorizer.PREFIX + "k1:");
        assertThat(approved.expiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThatThrownBy(() -> service.approve(asked.confirmationId(), "alice", null))
                .isInstanceOf(IllegalStateException.class);
        // Another request, even with the approval's identifier, is refused.
        assertThat(service.consume(ALICE_AGENT, "hash-2", asked.confirmationId())).isEmpty();
        // Another agent of the person, or the person, cannot use it.
        assertThat(service.consume(new ZeroTrustSubject(null, "alice", SubjectKind.DELEGATED_AGENT, "other-agent",
                null), "hash-1", asked.confirmationId())).isEmpty();
        assertThat(service.consume(ALICE_AGENT, "hash-1", null)).map(AgentConfirmation::status)
                .contains(AgentConfirmation.Status.USED);
        // The second use is refused.
        assertThat(service.consume(ALICE_AGENT, "hash-1", null)).isEmpty();
        assertThat(service.consume(ALICE_AGENT, "hash-1", asked.confirmationId())).isEmpty();
        assertThat(categories()).contains(AuditEventCategory.AGENT_CONFIRMATION_APPROVED,
                AuditEventCategory.AGENT_CONFIRMATION_REFUSED, AuditEventCategory.AGENT_CONFIRMATION_USED);
    }

    @Test
    void anApprovalWhoseFactsWereChangedDoesNotVerify() {
        AgentConfirmation asked = ask(ALICE_AGENT, "hash-1").orElseThrow();
        AgentConfirmation approved = service.approve(asked.confirmationId(), "alice", null);
        // Someone rewrites the stored approval to name the person as another approver.
        store.save(approved.decided(AgentConfirmation.Status.APPROVED, approved.decidedAt(), "mallory", null,
                approved.authorizationId(), approved.expiresAt()));

        assertThat(service.consume(ALICE_AGENT, "hash-1", null)).isEmpty();
        assertThat(store.find(asked.confirmationId())).map(AgentConfirmation::status)
                .contains(AgentConfirmation.Status.APPROVED);
    }

    @Test
    void aRefusalIsRecordedAndCannotBeUsed() {
        AgentConfirmation asked = ask(ALICE_AGENT, "hash-1").orElseThrow();

        assertThat(service.reject(asked.confirmationId(), "alice", "not now").status())
                .isEqualTo(AgentConfirmation.Status.REJECTED);
        assertThat(service.consume(ALICE_AGENT, "hash-1", asked.confirmationId())).isEmpty();
        assertThat(service.status(asked.confirmationId())).map(confirmation -> confirmation.status().refused())
                .contains(true);
        assertThat(categories()).contains(AuditEventCategory.AGENT_CONFIRMATION_REJECTED);
    }

    @Test
    void noAnswerInTimeIsARefusalAndAnApprovalNotUsedInTimeLapses() {
        AgentConfirmation waiting = ask(ALICE_AGENT, "hash-1").orElseThrow();
        AgentConfirmation approved = service.approve(ask(ALICE_AGENT, "hash-2").orElseThrow().confirmationId(),
                "alice", null);

        clock.advance(Duration.ofMinutes(16));

        assertThat(service.expireOverdue()).isEqualTo(2);
        assertThat(service.status(waiting.confirmationId())).map(AgentConfirmation::status)
                .contains(AgentConfirmation.Status.EXPIRED);
        assertThat(service.consume(ALICE_AGENT, "hash-2", approved.confirmationId())).isEmpty();
        assertThatThrownBy(() -> service.approve(waiting.confirmationId(), "alice", null))
                .isInstanceOf(IllegalStateException.class);
        // The person is told of the refusal of the request that waited, not of the lapsed approval.
        assertThat(delivered).extracting(AgentNotice::kind).containsExactly(AgentNotice.CONFIRMATION_REQUESTED,
                AgentNotice.CONFIRMATION_REQUESTED, AgentNotice.CONFIRMATION_EXPIRED);
        assertThat(service.expireOverdue()).isZero();
    }

    @Test
    void aReportRefusesTheRequestAndStopsTheAgentAtOnce() {
        AgentContainmentService containment = mock(AgentContainmentService.class);
        when(containment.onReport(any(), eq("alice"), any(), any())).thenReturn(List.of("AGENT_BLOCKED",
                "DELEGATION_REVOKED"));
        service.setContainment(containment);
        AgentConfirmation asked = ask(ALICE_AGENT, "hash-1").orElseThrow();

        assertThat(service.report(asked.confirmationId(), "alice", "I never asked for this").status())
                .isEqualTo(AgentConfirmation.Status.REPORTED);

        ArgumentCaptor<ZeroTrustSubject> stopped = ArgumentCaptor.forClass(ZeroTrustSubject.class);
        verify(containment).onReport(stopped.capture(), eq("alice"), eq("I never asked for this"), any());
        assertThat(stopped.getValue().storageKey()).isEqualTo("alice::agent::report-agent");
        assertThat(stopped.getValue().delegationId()).isEqualTo("DLG-1");
        assertThat(categories()).contains(AuditEventCategory.AGENT_CONFIRMATION_REPORTED);
    }

    private Optional<AgentConfirmation> ask(ZeroTrustSubject subject, String hash) {
        return service.request(new AgentConfirmationService.ConfirmationRequest(subject, hash, "POST",
                "/api/export?project=HX-310", AgentConfirmation.DECISION_CHALLENGE, "Export outside the delegation",
                "req-1", "https://app.test"));
    }

    private List<AuditEventCategory> categories() {
        ArgumentCaptor<AuditRecord> records = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit, atLeastOnce()).recordSync(records.capture());
        return records.getAllValues().stream().map(AuditRecord::getEventCategory).toList();
    }

    /** A clock the test moves on. */
    static final class MovingClock extends Clock {

        private Instant now;

        MovingClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
