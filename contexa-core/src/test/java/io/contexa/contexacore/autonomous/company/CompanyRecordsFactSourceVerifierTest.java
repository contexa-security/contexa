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
package io.contexa.contexacore.autonomous.company;

import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentDelegationRequest;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Approval;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Assignment;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.OnCall;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Person;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Usage;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.AssignmentRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.OnCallRecord;
import io.contexa.contexacore.autonomous.context.enricher.RecordedDelegationContextProvider;
import io.contexa.contexacore.verification.inspection.InspectedPrompt;
import io.contexa.contexacore.verification.inspection.PromptFactSourceVerifier.SourceFact;
import io.contexa.contexacore.verification.inspection.PromptFactSourceVerifier.SourceReading;
import io.contexa.contexacore.verification.inspection.PromptInspectionSubject;
import io.contexa.contexacore.verification.inspection.PromptInspectionUnavailableException;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** docs/agent OC-4: the source truth check reads Contexa's own company records and delegations again. */
class CompanyRecordsFactSourceVerifierTest {

    private static final Instant AT = Instant.parse("2026-09-30T05:30:00Z");

    private final InMemoryCompanyRecordStore store = new InMemoryCompanyRecordStore();
    private final InMemoryDelegationRegistry delegations = new InMemoryDelegationRegistry();
    private final CompanyRecordsFactSourceVerifier verifier = new CompanyRecordsFactSourceVerifier(store, delegations);

    CompanyRecordsFactSourceVerifierTest() {
        store.put(null, new CompanyRecordSet(List.of(new Person("alice", "eng-k", null)), null,
                List.of(new Assignment("alice", "HX-310", "DESIGN", null, null)),
                List.of(new Approval("APR-1", "alice", "pm-11", "HX-310", "DATA_EXPORT", null, 500, "APPROVED",
                        AT.minus(Duration.ofDays(1)), AT.plus(Duration.ofDays(1)), null, true, null, null)),
                null, List.of(new OnCall("ONC-1", "alice", "PLATFORM", AT.minus(Duration.ofHours(1)),
                AT.plus(Duration.ofHours(4)))), null, null,
                List.of(new Usage("job-1", "alice", "HX-310", 120, AT.minus(Duration.ofHours(2)))), null, null),
                "hr-sync", AT.minus(Duration.ofDays(2)));
    }

    @Test
    void theRecordsTheDecisionUsedAreReadAgain() {
        CanonicalSecurityContext context = context("alice", 300, new AssignmentRecord("HX-310", true, "DESIGN"));
        String prompt = """
                === DECISION FACTS ===
                [F3] Approval: APR-1 by pm-11, APPROVED, HX-310, up to 500 items, used 120 before this request
                [F4] Assignment: assigned to HX-310 (DESIGN)
                [F8] OnCall: not on call
                """;

        SourceReading reading = verifier.read(subject(context, prompt));

        assertThat(reading.recordsKept()).isTrue();
        assertThat(reading.facts()).extracting(SourceFact::entry, SourceFact::fragment).containsExactly(
                tuple("OnCall", "on call"),
                tuple("Assignment", "assigned to HX-310"),
                tuple("Approval", "APR-1 by pm-11"),
                tuple("Approval", "up to 500 items"),
                tuple("Approval", "used 120 before this request"));
    }

    @Test
    void accountManagementOverTheLimitAndRecordsNotLookedUpAreReadAsThePromptStatesThem() {
        CanonicalSecurityContext customer = context("alice", 900, new AssignmentRecord("C-0042", false,
                CompanyRecordSet.ACCOUNT_MANAGER));
        customer.getFrictionProfile().setOnCall(null);
        List<SourceFact> facts = verifier.read(subject(customer, """
                === DECISION FACTS ===
                [F3] Approval: APR-1 by pm-11, APPROVED, HX-310, up to 500 items, valid 09-29 05:30..10-01 05:30
                """)).facts();

        assertThat(facts).extracting(SourceFact::fragment).containsExactly("not the account manager of C-0042",
                "APR-1 by pm-11", "up to 500 items");
    }

    @Test
    void aDecisionWithoutCompanyRecordsHasNothingToCompareAndAPersonGoneIsRecordsNotKept() {
        CanonicalSecurityContext plain = context("alice", null, null);
        plain.setFrictionProfile(null);
        assertThat(verifier.read(subject(plain, "")).facts()).isEmpty();

        store.deleteSubject("alice");
        SourceReading gone = verifier.read(subject(context("alice", 300, new AssignmentRecord("HX-310", true,
                "DESIGN")), ""));
        assertThat(gone.recordsKept()).isFalse();
        assertThat(gone.notKeptRef()).isEqualTo("contexa company records (person)");
    }

    @Test
    void theDelegationTheDecisionUsedIsReadAgainFromTheRegistry() {
        AgentDelegation delegation = delegations.record(new AgentDelegationRequest(null, "alice", "report-agent",
                null, "REPORTING", null, List.of("READ"), List.of("HX-310"), false, null, null,
                AT.minus(Duration.ofHours(1)), AT.plus(Duration.ofHours(8)), "alice", AT.minus(Duration.ofHours(1))));
        CanonicalSecurityContext context = context("alice", null, null);
        context.setFrictionProfile(null);
        context.setDelegation(CanonicalSecurityContext.Delegation.builder().delegated(true).agentId("report-agent")
                .build());
        context.getAttributes().put(RecordedDelegationContextProvider.RECORD_ID_ATTRIBUTE, delegation.delegationId());

        assertThat(verifier.read(subject(context, "")).facts()).extracting(SourceFact::entry, SourceFact::fragment)
                .containsExactly(
                        tuple("Delegation", "agent report-agent for alice"),
                        tuple("Delegation", "objective REPORTING"),
                        tuple("RecordProvenance", "delegation "
                                + delegation.delegationId() + " recorded by alice"));

        context.getAttributes().put(RecordedDelegationContextProvider.RECORD_ID_ATTRIBUTE, "dlg-gone");
        assertThat(verifier.read(subject(context, "")).notKeptRef()).isEqualTo("contexa delegation registry");
    }

    @Test
    void aStoreThatCannotBeReadNowHasThePackageInspectedLater() {
        CompanyRecordStore failing = mock(CompanyRecordStore.class);
        when(failing.ofSubject(any(), any())).thenThrow(new DataAccessResourceFailureException("down"));

        assertThatThrownBy(() -> new CompanyRecordsFactSourceVerifier(failing, null).read(subject(
                context("alice", 300, new AssignmentRecord("HX-310", true, "DESIGN")), "")))
                .isInstanceOf(PromptInspectionUnavailableException.class);
    }

    private static CanonicalSecurityContext context(String user, Integer items, AssignmentRecord assignment) {
        CanonicalSecurityContext context = new CanonicalSecurityContext();
        context.setActor(CanonicalSecurityContext.Actor.builder().userId(user).build());
        context.setRequestObservedAt(AT);
        context.setResource(CanonicalSecurityContext.Resource.builder().scope("projectKey=HX-310").requestedItems(items)
                .build());
        Map<String, Object> attributes = new HashMap<>();
        context.setAttributes(attributes);
        FrictionProfile friction = new FrictionProfile();
        friction.setAssignment(assignment);
        friction.setOnCall(OnCallRecord.builder().onCall(true).build());
        friction.setCheckedRecordKinds(List.of("ASSIGNMENT", "ON_CALL"));
        friction.setRecordsHolderId(user);
        context.setFrictionProfile(friction);
        return context;
    }

    private static PromptInspectionSubject subject(CanonicalSecurityContext context, String prompt) {
        PromptInspectionSubject subject = mock(PromptInspectionSubject.class);
        when(subject.canonicalContext()).thenReturn(context);
        when(subject.prompt()).thenReturn(InspectedPrompt.parse(prompt));
        return subject;
    }
}
