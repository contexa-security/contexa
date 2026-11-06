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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.AgentConfirmationFacts;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.context.RequestSecurityContextAttributes;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.agent.AgentConfirmation;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationService;
import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentDelegationRequest;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentConfirmationStore;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import io.contexa.contexacore.autonomous.agent.SignedAgentConfirmationAuthorizer;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.agent.AgentRequestBinding;
import io.contexa.contexacore.autonomous.agent.AgentScopeService;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentScopeStore;
import io.contexa.contexacore.autonomous.agent.ReadOnlyAgentScopeNarrower;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.agent.AgentCallGuard;
import io.contexa.contexacore.autonomous.agent.AgentNotice;
import io.contexa.contexacore.autonomous.agent.AgentNotices;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentNoticeStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * docs/agent A5-2, A5-9, F-2: an agent's request a CHALLENGE (or an ended delegation) holds waits for its accountable
 * person; the approved request sent again runs once, with its own body and authorities; a revoked delegation refuses
 * the request; a request with nothing to confirm passes untouched.
 */
class AgentConfirmationGateTest {

    private static final Instant NOW = Instant.parse("2026-10-24T02:00:00Z");
    private static final String BODY = "{\"project\":\"HX-310\",\"documents\":40}";

    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final InMemoryAgentConfirmationStore store = new InMemoryAgentConfirmationStore();
    private final AgentConfirmationService confirmations = new AgentConfirmationService(store,
            new SignedAgentConfirmationAuthorizer(HmacEvidenceSigner.of(Map.of("k1", Base64.getEncoder()
                    .encodeToString("0123456789abcdef0123456789abcdef".getBytes())), "k1")), null, null, null,
            Duration.ofMinutes(15), clock);
    private final InMemoryDelegationRegistry delegations = new InMemoryDelegationRegistry(Duration.ofDays(30), clock);
    private final RecordingWriter writer = new RecordingWriter();
    private final AgentConfirmationGate gate = new AgentConfirmationGate(confirmations,
            new InMemoryZeroTrustActionRepository(), writer, 1024, "https://app.test", clock);
    private final ZeroTrustSubject subject = new ZeroTrustSubject(null, "alice", SubjectKind.DELEGATED_AGENT,
            "report-agent", null);

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    /** The person reads the query, a secret in it excepted; the request confirmed stays the very request. */
    @Test
    void aSecretInTheQueryIsMaskedAndTheRequestStaysBound() throws Exception {
        MockHttpServletRequest asked = request(BODY);
        asked.setQueryString("format=zip&token=s3cr3t-value&project=HX-310");

        send(asked, ZeroTrustAction.CHALLENGE);

        String id = (String) writer.details.get("confirmationId");
        assertThat(store.find(id).orElseThrow().target())
                .isEqualTo("/api/exports?format=zip&token=[MASKED]&project=HX-310");
        confirmations.approve(id, "alice", null);

        MockHttpServletRequest another = request(BODY);
        another.setQueryString("format=zip&token=another-value&project=HX-310");
        another.addHeader(AgentConfirmationGate.CONFIRMATION_HEADER, id);
        assertThat(send(another, ZeroTrustAction.CHALLENGE).went()).as("another value is another request").isFalse();

        MockHttpServletRequest same = request(BODY);
        same.setQueryString("format=zip&token=s3cr3t-value&project=HX-310");
        same.addHeader(AgentConfirmationGate.CONFIRMATION_HEADER, id);
        assertThat(send(same, ZeroTrustAction.CHALLENGE).went()).isTrue();
    }

    @Test
    void aChallengedRequestWaitsAndTheApprovedRequestRunsOnceWithItsBodyAndAuthorities() throws Exception {
        Recording first = send(request(BODY), ZeroTrustAction.CHALLENGE);
        assertThat(first.went()).isFalse();
        assertThat(writer.status).isEqualTo(403);
        assertThat(writer.details).containsEntry("error", ZeroTrustChallengeFilter.AGENT_CONFIRMATION_REQUIRED)
                .containsEntry("trigger", AgentConfirmation.DECISION_CHALLENGE)
                .containsEntry("status", "PENDING")
                .containsKey("expiresAt");
        String id = (String) writer.details.get("confirmationId");
        assertThat(writer.details.get("statusUrl")).isEqualTo("/contexa/api/agent-confirmations/" + id);
        // The same request again is answered with the same confirmation.
        send(request(BODY), ZeroTrustAction.CHALLENGE);
        assertThat(writer.details.get("confirmationId")).isEqualTo(id);
        confirmations.approve(id, "alice", null);

        // Another request is not the approved one.
        Recording other = send(request("{\"project\":\"GB-500\",\"documents\":40}"), ZeroTrustAction.CHALLENGE);
        assertThat(other.went()).isFalse();
        assertThat(writer.details.get("confirmationId")).isNotEqualTo(id);

        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject("alice")
                .issuedAt(NOW).expiresAt(NOW.plusSeconds(300)).build();
        JwtAuthenticationToken own = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("SCOPE_reports.export")), "alice");
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority(ZeroTrustAction.CHALLENGE.getGrantedAuthority())), "alice"));
        MockHttpServletRequest approved = request(BODY);
        approved.setAttribute("contexa.zeroTrust.agentAuthenticationBeforeChallenge", own);
        Recording ran = send(approved, ZeroTrustAction.CHALLENGE);

        assertThat(ran.went()).isTrue();
        assertThat(ran.body()).isEqualTo(BODY);
        assertThat(ran.confirmation()).isEqualTo(id);
        // docs/agent F-5: what the person confirmed travels with the request into its decision context.
        assertThat(ran.confirmationFacts()).containsEntry(AgentConfirmationFacts.ID, id)
                .containsEntry(AgentConfirmationFacts.DECIDED_BY, "alice")
                .containsEntry(AgentConfirmationFacts.TRIGGER, AgentConfirmation.DECISION_CHALLENGE)
                .containsKeys(AgentConfirmationFacts.DECIDED_AT, AgentConfirmationFacts.ASKED_AT,
                        AgentConfirmationFacts.USED_AT);
        assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
                .extracting(GrantedAuthority::getAuthority).containsExactly("SCOPE_reports.export");
        // The approval was used: the same request needs a new confirmation.
        Recording again = send(request(BODY), ZeroTrustAction.CHALLENGE);
        assertThat(again.went()).isFalse();
        assertThat(writer.details.get("confirmationId")).isNotEqualTo(id);
    }

    /** CF-22: a request with nothing to confirm is bound too (a CHALLENGE decided in it may ask), its body whole. */
    @Test
    void aRequestWithNothingToConfirmPassesWithItsBodyWhole() throws Exception {
        MockHttpServletRequest request = request(BODY);

        Recording passed = send(request, ZeroTrustAction.ALLOW);

        assertThat(passed.went()).isTrue();
        assertThat(passed.body()).isEqualTo(BODY);
        assertThat(passed.confirmation()).isNull();
        assertThat(store.list(null, 10)).isEmpty();
    }

    @Test
    void aRevokedDelegationRefusesTheRequestAndAnExpiredOneAsksThePerson() throws Exception {
        gate.setDelegationRegistry(delegations);
        AgentDelegation revoked = delegations.record(delegation(NOW.minusSeconds(7200), NOW.plusSeconds(7200)));
        delegations.revoke(revoked.delegationId(), "alice", "done");

        Recording refused = send(request(BODY), ZeroTrustAction.ALLOW);
        assertThat(refused.went()).isFalse();
        assertThat(writer.details).containsEntry("error", AgentConfirmationGate.DELEGATION_REVOKED)
                .containsEntry("delegationId", revoked.delegationId());

        InMemoryDelegationRegistry expiredOnly = new InMemoryDelegationRegistry(Duration.ofDays(30),
                Clock.fixed(NOW.minus(Duration.ofDays(2)), ZoneOffset.UTC));
        expiredOnly.record(delegation(NOW.minus(Duration.ofDays(2)), NOW.minusSeconds(7200)));
        gate.setDelegationRegistry(expiredOnly);
        Recording asked = send(request(BODY), ZeroTrustAction.ALLOW);
        assertThat(asked.went()).isFalse();
        assertThat(writer.details).containsEntry("trigger", AgentConfirmation.DELEGATION_ENDED);
        assertThat(store.find((String) writer.details.get("confirmationId")))
                .map(AgentConfirmation::reason).hasValueSatisfying(reason -> assertThat(reason).contains("expired"));
    }

    /**
     * F-2 in a tenant: the ended delegation is found in the request's tenant, and (CF-13) one recorded without a
     * tenant too, as the decision's own lookup finds it; the request is bound in its tenant. A delegation the request
     * names but that another person gave is not the request's.
     */
    @Test
    void aTenantsEndedDelegationAndOneRecordedWithoutATenantBothAskThePerson() throws Exception {
        ZeroTrustSubject inTenant = new ZeroTrustSubject("tenant-a", "alice", SubjectKind.DELEGATED_AGENT,
                "report-agent", null);
        Clock earlier = Clock.fixed(NOW.minus(Duration.ofDays(2)), ZoneOffset.UTC);
        InMemoryDelegationRegistry tenantRecords = new InMemoryDelegationRegistry(Duration.ofDays(30), earlier);
        tenantRecords.record(delegation("tenant-a", "alice", NOW.minus(Duration.ofDays(2)), NOW.minusSeconds(7200)));
        gate.setDelegationRegistry(tenantRecords);

        assertThat(send(request(BODY), ZeroTrustAction.ALLOW, inTenant).went()).isFalse();
        assertThat(writer.details).containsEntry("trigger", AgentConfirmation.DELEGATION_ENDED);
        AgentConfirmation asked = store.find((String) writer.details.get("confirmationId")).orElseThrow();
        assertThat(asked.tenantId()).isEqualTo("tenant-a");
        assertThat(asked.requestHash()).isEqualTo(AgentRequestBinding.hash("tenant-a", "alice", "report-agent",
                "POST", "/api/exports", "format=zip",
                AgentRequestBinding.sha256Hex(BODY.getBytes(StandardCharsets.UTF_8)), null));

        InMemoryDelegationRegistry singleTenant = new InMemoryDelegationRegistry(Duration.ofDays(30), earlier);
        singleTenant.record(delegation(null, "alice", NOW.minus(Duration.ofDays(2)), NOW.minusSeconds(7200)));
        AgentDelegation bobs = singleTenant.record(delegation(null, "bob", NOW.minus(Duration.ofDays(2)),
                NOW.plus(Duration.ofDays(1))));
        gate.setDelegationRegistry(singleTenant);
        writer.details = new HashMap<>();
        assertThat(send(request("{}"), ZeroTrustAction.ALLOW, inTenant).went()).isFalse();
        assertThat(writer.details).containsEntry("trigger", AgentConfirmation.DELEGATION_ENDED);

        writer.details = new HashMap<>();
        ZeroTrustSubject namingBobs = new ZeroTrustSubject("tenant-a", "alice", SubjectKind.DELEGATED_AGENT,
                "report-agent", bobs.delegationId());
        assertThat(send(request("[]"), ZeroTrustAction.ALLOW, namingBobs).went()).isFalse();
        assertThat(writer.details).containsEntry("trigger", AgentConfirmation.DELEGATION_ENDED);
    }

    /**
     * F-2 at the request's recorded time: a delegation in force at the time the host recorded for the request lets it
     * on, as the decision reads the delegation at that time; a revocation made since still stops it.
     */
    @Test
    void theDelegationIsReadAtTheRequestsRecordedTimeButARevocationCountsFromWhenItWasMade() throws Exception {
        Clock earlier = Clock.fixed(NOW.minus(Duration.ofMinutes(150)), ZoneOffset.UTC);
        InMemoryDelegationRegistry records = new InMemoryDelegationRegistry(Duration.ofDays(30), earlier);
        AgentDelegation recorded = records.record(delegation(NOW.minus(Duration.ofDays(2)),
                NOW.minus(Duration.ofHours(2))));
        gate.setDelegationRegistry(records);

        assertThat(send(recordedAt(request(BODY), NOW.minus(Duration.ofHours(3))), ZeroTrustAction.ALLOW).went())
                .isTrue();
        assertThat(send(request(BODY), ZeroTrustAction.ALLOW).went()).isFalse();
        assertThat(writer.details).containsEntry("trigger", AgentConfirmation.DELEGATION_ENDED);

        records.revoke(recorded.delegationId(), "alice", "no longer needed");
        assertThat(send(recordedAt(request(BODY), NOW.minus(Duration.ofHours(3))), ZeroTrustAction.ALLOW).went())
                .isFalse();
        assertThat(writer.details).containsEntry("error", AgentConfirmationGate.DELEGATION_REVOKED);
    }

    /**
     * CF-22 (A5-2): a CHALLENGE decided in the request itself (the exception handler asks the gate) asks the person
     * to confirm that very request; the approved request sent again runs once, with its body.
     */
    @Test
    void aChallengeDecidedInTheRequestAsksForThatVeryRequestAndTheApprovedOneRunsOnce() throws Exception {
        Recording decided = new Recording();
        decided.answer = (request, response) -> assertThat(gate.answerDecidedChallenge(request, response, subject))
                .isTrue();
        assertThat(gate.filter(request(BODY), new MockHttpServletResponse(), decided, subject, ZeroTrustAction.ALLOW))
                .isFalse();
        assertThat(decided.body()).isEqualTo(BODY);
        assertThat(writer.status).isEqualTo(403);
        assertThat(writer.details).containsEntry("error", ZeroTrustChallengeFilter.AGENT_CONFIRMATION_REQUIRED)
                .containsEntry("trigger", AgentConfirmation.DECISION_CHALLENGE);
        String id = (String) writer.details.get("confirmationId");
        assertThat(store.find(id)).map(AgentConfirmation::requestHash).contains(AgentRequestBinding.hash(null,
                "alice", "report-agent", "POST", "/api/exports", "format=zip",
                AgentRequestBinding.sha256Hex(BODY.getBytes(StandardCharsets.UTF_8)), null));
        confirmations.approve(id, "alice", null);

        MockHttpServletRequest approved = request(BODY);
        approved.addHeader(AgentConfirmationGate.CONFIRMATION_HEADER, id);
        Recording ran = send(approved, ZeroTrustAction.CHALLENGE);
        assertThat(ran.went()).isTrue();
        assertThat(ran.body()).isEqualTo(BODY);
        assertThat(ran.confirmation()).isEqualTo(id);
    }

    /** CF-22: a body over the bound size reaches the application whole and is not bound; no confirmation asks for it. */
    @Test
    void aBodyOverTheBoundSizeReachesTheApplicationWholeAndIsNotBound() throws Exception {
        String large = "x".repeat(3000);
        MockHttpServletRequest chunked = new MockHttpServletRequest("POST", "/api/exports") {
            @Override
            public long getContentLengthLong() {
                return -1;
            }
        };
        chunked.setContentType("application/json");
        chunked.setContent(large.getBytes(StandardCharsets.UTF_8));
        Recording passed = new Recording();
        passed.answer = (request, response) -> assertThat(gate.answerDecidedChallenge(request, response, subject))
                .isFalse();

        assertThat(gate.filter(chunked, new MockHttpServletResponse(), passed, subject, ZeroTrustAction.ALLOW))
                .isTrue();
        assertThat(passed.body()).isEqualTo(large);
        assertThat(store.list(null, 10)).isEmpty();
    }

    /** docs/agent A5-4: outside the narrowed scope a request is refused, unless the person confirmed that one. */
    @Test
    void aRequestOutsideTheNarrowedScopeIsRefusedUnlessThePersonConfirmedIt() throws Exception {
        narrowed();

        Recording refused = send(request(BODY), ZeroTrustAction.ALLOW);
        assertThat(refused.went()).isFalse();
        assertThat(writer.details).containsEntry("error", AgentConfirmationGate.SCOPE_NARROWED)
                .containsEntry("operation", "EXPORT")
                .containsEntry("allowed", List.of("READ"));
        MockHttpServletRequest read = new MockHttpServletRequest("GET", "/api/projects/HX-310/documents");
        assertThat(send(read, ZeroTrustAction.ALLOW).went()).isTrue();

        // The person confirms this very request; it runs once despite the narrowing.
        String hash = AgentRequestBinding.hash(null, "alice", "report-agent", "POST", "/api/exports", "format=zip",
                AgentRequestBinding.sha256Hex(BODY.getBytes(StandardCharsets.UTF_8)), null);
        AgentConfirmation asked = confirmations.request(new AgentConfirmationService.ConfirmationRequest(subject, hash,
                "POST", "/api/exports?format=zip", AgentConfirmation.REQUESTED, null, null, null)).orElseThrow();
        confirmations.approve(asked.confirmationId(), "alice", null);
        MockHttpServletRequest confirmed = request(BODY);
        confirmed.addHeader(AgentConfirmationGate.CONFIRMATION_HEADER, asked.confirmationId());
        Recording ran = send(confirmed, ZeroTrustAction.ALLOW);
        assertThat(ran.went()).isTrue();
        assertThat(ran.confirmation()).isEqualTo(asked.confirmationId());
        assertThat(send(request(BODY), ZeroTrustAction.ALLOW).went()).isFalse();
    }

    /** A narrowed agent reaches no write and no export by the way its path is spelled, as the application routes it. */
    @Test
    void aNarrowedAgentReachesNoWriteAndNoExportByTheWayItsPathIsSpelled() throws Exception {
        narrowed();
        Routed application = new Routed();
        MockMvc gated = MockMvcBuilders.standaloneSetup(application).addFilter(
                (request, response, chain) -> gate.filter((HttpServletRequest) request,
                        (HttpServletResponse) response, chain, subject, ZeroTrustAction.ALLOW)).build();

        // Without the gate this reaches the export: the spelling is what routing reads.
        MockMvcBuilders.standaloneSetup(application).build().perform(get(URI.create("/api/%65xport/x")));
        assertThat(application.reached).containsExactly("export");
        application.reached.clear();

        gated.perform(get(URI.create("/api/%65xport/x")));
        assertThat(writer.details).containsEntry("error", AgentConfirmationGate.SCOPE_NARROWED)
                .containsEntry("operation", "EXPORT");
        gated.perform(delete("/api/lists/7"));
        assertThat(writer.details).containsEntry("operation", "DELETE");
        gated.perform(post("/api/search/x"));
        assertThat(writer.details).containsEntry("operation", "WRITE");
        assertThat(application.reached).isEmpty();

        gated.perform(get("/api/lists/7"));
        assertThat(application.reached).containsExactly("list");
    }

    /** docs/agent A5-7: past its call limit an agent is slowed down; its refusals count toward the denial alarm. */
    @Test
    void pastItsCallLimitAnAgentIsSlowedDownAndItsRefusalsCount() throws Exception {
        SecurityZeroTrustProperties.CallLimit limits = new SecurityZeroTrustProperties.CallLimit();
        limits.setPerDelegationPerMinute(2);
        SecurityZeroTrustProperties.DenialAlarm alarm = new SecurityZeroTrustProperties.DenialAlarm();
        alarm.setMinRequests(3);
        InMemoryAgentNoticeStore notices = new InMemoryAgentNoticeStore();
        gate.setCallGuard(new AgentCallGuard(limits, alarm, new AgentNotices(notices, null), null, null, clock));

        MockHttpServletRequest first = new MockHttpServletRequest("GET", "/api/projects");
        assertThat(send(first, ZeroTrustAction.ALLOW).went()).isTrue();
        assertThat(first.getAttribute(BridgeRequestAttributes.AGENT_RECENT_CALLS)).isEqualTo(1);
        assertThat(send(new MockHttpServletRequest("GET", "/api/projects"), ZeroTrustAction.ALLOW).went()).isTrue();

        MockHttpServletResponse slowed = new MockHttpServletResponse();
        assertThat(gate.filter(new MockHttpServletRequest("GET", "/api/projects"), slowed, new Recording(), subject,
                ZeroTrustAction.ALLOW)).isFalse();
        assertThat(writer.status).isEqualTo(429);
        assertThat(writer.details).containsEntry("error", AgentConfirmationGate.CALL_LIMIT)
                .containsEntry("scope", "DELEGATION");
        assertThat(slowed.getHeader("Retry-After")).isNotBlank();
        // Three requests, one of them refused, then another refused: the refusal rate reaches the alarm.
        gate.filter(new MockHttpServletRequest("GET", "/api/projects"), new MockHttpServletResponse(),
                new Recording(), subject, ZeroTrustAction.ALLOW);
        assertThat(notices.forRecipient("alice", 5)).extracting(AgentNotice::kind)
                .containsExactly(AgentNotice.DENIAL_RATE_ALARM);
    }

    /** docs/agent G-9: in the report-only mode an ended delegation and a narrowed scope let the request on. */
    @Test
    void inTheReportOnlyModeTheGatesOwnChecksLetTheRequestOn() throws Exception {
        gate.setEnforcing(() -> false);
        gate.setDelegationRegistry(delegations);
        AgentDelegation revoked = delegations.record(delegation(NOW.minusSeconds(7200), NOW.plusSeconds(7200)));
        delegations.revoke(revoked.delegationId(), "alice", "done");
        AgentScopeService scopes = new AgentScopeService(new InMemoryAgentScopeStore(),
                new ReadOnlyAgentScopeNarrower(Duration.ofHours(1), 0.7), null, clock);
        SecurityEvent decided = SecurityEvent.builder().userId("alice").build();
        decided.addMetadata("executionSubjectKind", "DELEGATED_AGENT");
        decided.addMetadata("agentId", "report-agent");
        scopes.onDecision(decided, ProcessingResult.builder().success(true).action("BLOCK").riskScore(0.9).build());
        gate.setScopes(scopes);

        Recording observed = send(request(BODY), ZeroTrustAction.ALLOW);

        assertThat(observed.went()).isTrue();
        assertThat(observed.body()).isEqualTo(BODY);
        assertThat(store.list(null, 10)).isEmpty();
    }

    /** The link starts at the configured address and the application's path; a host the agent sent reaches no one. */
    @Test
    void theConfirmationLinkStartsAtTheConfiguredAddressNeverAtTheHostTheAgentSent() throws Exception {
        List<AgentNotice> mailed = new ArrayList<>();
        AgentConfirmationService mailing = new AgentConfirmationService(store,
                new SignedAgentConfirmationAuthorizer(HmacEvidenceSigner.of(Map.of("k1", Base64.getEncoder()
                        .encodeToString("0123456789abcdef0123456789abcdef".getBytes())), "k1")),
                new AgentNotices(new InMemoryAgentNoticeStore(), notice -> {
                    mailed.add(notice);
                    return "MAIL";
                }), null, null, Duration.ofMinutes(15), clock);
        AgentConfirmationGate configured = new AgentConfirmationGate(mailing, new InMemoryZeroTrustActionRepository(),
                writer, 1024, " https://app.test/ ", clock);
        AgentConfirmationGate unset = new AgentConfirmationGate(mailing, new InMemoryZeroTrustActionRepository(),
                writer, 1024, null, clock);

        configured.filter(fromAnotherHost("{\"n\":1}"), new MockHttpServletResponse(), new Recording(), subject,
                ZeroTrustAction.CHALLENGE);
        unset.filter(fromAnotherHost("{\"n\":2}"), new MockHttpServletResponse(), new Recording(), subject,
                ZeroTrustAction.CHALLENGE);

        assertThat(mailed).extracting(AgentNotice::link).satisfiesExactly(
                link -> assertThat(link).startsWith("https://app.test/ctx/contexa/agent-confirmations/"),
                link -> assertThat(link).startsWith("/ctx/contexa/agent-confirmations/"));
    }

    private static MockHttpServletRequest fromAnotherHost(String body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/ctx/api/exports");
        request.setContextPath("/ctx");
        request.setServerName("attacker.test");
        request.addHeader("Host", "attacker.test");
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        request.setContentType("application/json");
        return request;
    }

    /**
     * A person confirms what they can read whole: a target longer than a confirmation keeps asks no one and is refused
     * as a body too large to bind is, decided in the request as well; one that fits is kept whole.
     */
    @Test
    void aTargetLongerThanAConfirmationKeepsAsksNoOneAndIsRefused() throws Exception {
        MockHttpServletRequest fits = request(BODY);
        fits.setQueryString("q=" + "a".repeat(AgentConfirmation.MAX_TARGET_LENGTH - "/api/exports?q=".length()));
        send(fits, ZeroTrustAction.CHALLENGE);
        assertThat(writer.status).isEqualTo(403);
        assertThat(store.find((String) writer.details.get("confirmationId"))).map(AgentConfirmation::target)
                .contains("/api/exports?" + fits.getQueryString());

        MockHttpServletRequest past = request(BODY);
        past.setQueryString(fits.getQueryString() + "a");
        Recording refused = send(past, ZeroTrustAction.CHALLENGE);

        assertThat(refused.went()).isFalse();
        assertThat(writer.status).isEqualTo(413);
        assertThat(writer.details).containsEntry("error", AgentConfirmationGate.CONFIRMATION_UNBINDABLE);
        assertThat(store.list(null, 10)).hasSize(1);

        MockHttpServletRequest decidedPast = request(BODY);
        decidedPast.setQueryString(past.getQueryString());
        Recording decided = new Recording();
        decided.answer = (request, response) -> assertThat(gate.answerDecidedChallenge(request, response, subject))
                .isFalse();
        gate.filter(decidedPast, new MockHttpServletResponse(), decided, subject, ZeroTrustAction.ALLOW);
        assertThat(store.list(null, 10)).hasSize(1);
    }

    @Test
    void aRequestTooLargeToBindIsRefusedWhenItNeedsAConfirmation() throws Exception {
        Recording refused = send(request("x".repeat(2048)), ZeroTrustAction.CHALLENGE);

        assertThat(refused.went()).isFalse();
        assertThat(writer.status).isEqualTo(413);
        assertThat(writer.details).containsEntry("error", AgentConfirmationGate.CONFIRMATION_UNBINDABLE);
    }

    private Recording send(MockHttpServletRequest request, ZeroTrustAction action) throws Exception {
        return send(request, action, subject);
    }

    /** A decision narrowed the agent to reading. */
    private void narrowed() {
        AgentScopeService scopes = new AgentScopeService(new InMemoryAgentScopeStore(),
                new ReadOnlyAgentScopeNarrower(Duration.ofHours(1), 0.7), null, clock);
        SecurityEvent decided = SecurityEvent.builder().userId("alice").build();
        decided.addMetadata("executionSubjectKind", "DELEGATED_AGENT");
        decided.addMetadata("agentId", "report-agent");
        scopes.onDecision(decided, ProcessingResult.builder().success(true).action("BLOCK").riskScore(0.9).build());
        gate.setScopes(scopes);
    }

    private Recording send(MockHttpServletRequest request, ZeroTrustAction action, ZeroTrustSubject from)
            throws Exception {
        Recording recording = new Recording();
        boolean went = gate.filter(request, new MockHttpServletResponse(), recording, from, action);
        recording.went = went;
        return recording;
    }

    private static MockHttpServletRequest request(String body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/exports");
        request.setQueryString("format=zip");
        request.setContentType("application/json");
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        request.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, new DelegationStamp("alice", "report-agent",
                true, null, null, null, List.of(), List.of(), null, null, null, null, Map.of()));
        return request;
    }

    private static MockHttpServletRequest recordedAt(MockHttpServletRequest request, Instant observedAt) {
        request.setAttribute(RequestSecurityContextAttributes.Field.OBSERVED_AT.canonicalAttributeKey(), observedAt);
        return request;
    }

    private static AgentDelegationRequest delegation(Instant from, Instant until) {
        return delegation(null, "alice", from, until);
    }

    private static AgentDelegationRequest delegation(String tenantId, String delegator, Instant from, Instant until) {
        return new AgentDelegationRequest(tenantId, delegator, "report-agent", null, "REPORTING",
                "Export this week's HX-310 design review packages", List.of("EXPORT"), List.of("HX-310"), null, null,
                null, from, until, null, null);
    }

    /** An application with the routes an agent is after. */
    @RestController
    private static final class Routed {

        private final List<String> reached = new ArrayList<>();

        @GetMapping("/api/export/{id}")
        void export(@PathVariable("id") String id) {
            reached.add("export");
        }

        @RequestMapping("/api/lists/{id}")
        void list(@PathVariable("id") String id) {
            reached.add("list");
        }

        @PostMapping("/api/search/{id}")
        void search(@PathVariable("id") String id) {
            reached.add("search");
        }
    }

    /** The application's answer to a request, written after the gate let it on. */
    private interface Answer {
        void write(HttpServletRequest request, HttpServletResponse response) throws IOException;
    }

    /** The chain after the gate: what reached it. */
    private static final class Recording implements FilterChain {

        private boolean went;
        private HttpServletRequest request;
        private String body;
        /** What the application does after reading the body: here, a CHALLENGE decided in the request. */
        private Answer answer;

        @Override
        public void doFilter(ServletRequest request, ServletResponse response) throws IOException {
            this.request = (HttpServletRequest) request;
            this.body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (answer != null) {
                answer.write((HttpServletRequest) request, (HttpServletResponse) response);
            }
        }

        boolean went() {
            return went;
        }

        HttpServletRequest request() {
            return request;
        }

        String body() {
            return body;
        }

        String confirmation() {
            return request != null ? (String) request.getAttribute(BridgeRequestAttributes.AGENT_CONFIRMATION) : null;
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> confirmationFacts() {
            return request != null
                    ? (Map<String, Object>) request.getAttribute(BridgeRequestAttributes.AGENT_CONFIRMATION_FACTS)
                    : null;
        }
    }

    /** The answers the gate wrote. */
    private static final class RecordingWriter implements AuthResponseWriter {

        private int status;
        private Map<String, Object> details = new HashMap<>();
        private final List<String> codes = new ArrayList<>();

        @Override
        public void writeSuccessResponse(HttpServletResponse response, Object data, int status) {
            this.status = status;
        }

        @Override
        public void writeErrorResponse(HttpServletResponse response, int status, String errorCode, String errorMessage,
                                       String path) {
            this.status = status;
            codes.add(errorCode);
        }

        @Override
        public void writeErrorResponse(HttpServletResponse response, int status, String errorCode, String errorMessage,
                                       String requestUri, Map<String, Object> errorDetails) {
            this.status = status;
            this.details = new HashMap<>(errorDetails);
            codes.add(errorCode);
        }
    }
}
