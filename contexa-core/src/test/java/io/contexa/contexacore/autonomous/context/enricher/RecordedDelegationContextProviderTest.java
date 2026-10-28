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
package io.contexa.contexacore.autonomous.context.enricher;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.inference.ContextCoverageEvaluator;
import io.contexa.contexacore.autonomous.context.inference.MetadataObservedScopeInferenceService;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.context.registry.InMemoryResourceContextRegistry;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/** A1-4 (AG-1e): the delegation a host keeps in its business records reaches the canonical context and the prompt. */
class RecordedDelegationContextProviderTest {

    private static final Instant REQUESTED_AT = Instant.parse("2026-10-22T03:00:00Z");

    @Test
    void anAgentRequestTakesTheDelegationTheHostRecorded() {
        AtomicReference<DelegationRecordQuery> asked = new AtomicReference<>();
        RecordedDelegationContextProvider provider = new RecordedDelegationContextProvider(query -> {
            asked.set(query);
            return Optional.of(record("agent-7"));
        });
        CanonicalSecurityContext context = agentContext(CanonicalSecurityContext.Delegation.builder()
                .delegated(true).agentId("agent-7").build());
        context.getAttributes().put("delegationId", "dlg-42");

        provider.enrich(event(), context);

        assertThat(asked.get()).isEqualTo(new DelegationRecordQuery(
                "tenant-acme", "alice", "agent-7", "dlg-42", null, REQUESTED_AT));
        CanonicalSecurityContext.Delegation delegation = context.getDelegation();
        assertThat(delegation.getDelegated()).isTrue();
        assertThat(delegation.getObjectiveId()).isEqualTo("monthly-report");
        assertThat(delegation.getObjectiveFamily()).isEqualTo("REPORTING");
        assertThat(delegation.getObjectiveSummary()).isEqualTo("Prepare the October sales report");
        assertThat(delegation.getAllowedOperations()).containsExactly("READ");
        assertThat(delegation.getAllowedResources()).containsExactly("SALES_REPORT");
        assertThat(delegation.getApprovalRequired()).isTrue();
        assertThat(delegation.getPrivilegedExportAllowed()).isFalse();
        assertThat(delegation.getExpiresAt()).isEqualTo("2026-10-22T09:00:00Z");
        assertThat(context.getAttributes())
                .containsEntry(RecordedDelegationContextProvider.LOOKUP_ATTRIBUTE, "FOUND")
                .containsEntry(RecordedDelegationContextProvider.RECORD_ID_ATTRIBUTE, "dlg-42")
                .doesNotContainKey(RecordedDelegationContextProvider.CONFLICTS_ATTRIBUTE);
    }

    /** A2-10 (AG-12h): who wrote the delegation's record and when reach the context, as the host states them. */
    @Test
    void theRecordsAuthorAndTimeReachTheContext() {
        DelegationRecord written = new DelegationRecord("dlg-42", "alice", "agent-7", "monthly-report", "REPORTING",
                null, List.of("READ"), List.of("SALES_REPORT"), false, false, null,
                Instant.parse("2026-10-22T09:00:00Z"), "agent-7", Instant.parse("2026-10-22T02:58:00Z"));
        CanonicalSecurityContext stated = agentContext(CanonicalSecurityContext.Delegation.builder()
                .delegated(true).agentId("agent-7").build());
        CanonicalSecurityContext unstated = agentContext(CanonicalSecurityContext.Delegation.builder()
                .delegated(true).agentId("agent-7").build());

        new RecordedDelegationContextProvider(query -> Optional.of(written)).enrich(event(), stated);
        new RecordedDelegationContextProvider(query -> Optional.of(record("agent-7"))).enrich(event(), unstated);

        assertThat(stated.getAttributes())
                .containsEntry(RecordedDelegationContextProvider.RECORDED_BY_ATTRIBUTE, "agent-7")
                .containsEntry(RecordedDelegationContextProvider.RECORDED_AT_ATTRIBUTE, "2026-10-22T02:58:00Z");
        assertThat(unstated.getAttributes()).doesNotContainKeys(RecordedDelegationContextProvider.RECORDED_BY_ATTRIBUTE,
                RecordedDelegationContextProvider.RECORDED_AT_ATTRIBUTE);
    }

    @Test
    void aPersonsOwnRequestIsNotLookedUp() {
        AtomicReference<DelegationRecordQuery> asked = new AtomicReference<>();
        RecordedDelegationContextProvider provider = new RecordedDelegationContextProvider(query -> {
            asked.set(query);
            return Optional.empty();
        });
        CanonicalSecurityContext context = agentContext(CanonicalSecurityContext.Delegation.builder().build());

        provider.enrich(event(), context);

        assertThat(asked.get()).isNull();
        assertThat(context.getAttributes()).doesNotContainKey(RecordedDelegationContextProvider.LOOKUP_ATTRIBUTE);
    }

    @Test
    void theRecordNarrowsWhatTheTokenStatedAndNeverWidensIt() {
        RecordedDelegationContextProvider provider = new RecordedDelegationContextProvider(query -> Optional.of(
                new DelegationRecord("dlg-42", "alice", "agent-7", null, null, null,
                        List.of("READ"), List.of("SALES_REPORT", "HR_FILE"),
                        false, true, true, Instant.parse("2026-10-22T09:00:00Z"))));
        CanonicalSecurityContext context = agentContext(CanonicalSecurityContext.Delegation.builder()
                .delegated(true).agentId("agent-7")
                .allowedOperations(new ArrayList<>(List.of("READ", "EXPORT")))
                .allowedResources(new ArrayList<>(List.of("SALES_REPORT")))
                .approvalRequired(true)
                .privilegedExportAllowed(false)
                .expiresAt("2026-10-22T05:00:00Z")
                .build());

        provider.enrich(event(), context);

        CanonicalSecurityContext.Delegation delegation = context.getDelegation();
        assertThat(delegation.getAllowedOperations()).containsExactly("READ");
        assertThat(delegation.getAllowedResources()).containsExactly("SALES_REPORT");
        assertThat(delegation.getApprovalRequired()).isTrue();
        assertThat(delegation.getPrivilegedExportAllowed()).isFalse();
        assertThat(delegation.getContainmentOnly()).isTrue();
        assertThat(delegation.getExpiresAt()).isEqualTo("2026-10-22T05:00:00Z");
    }

    @Test
    void listsWithNothingInCommonKeepTheRecordsListRatherThanBecomingEmpty() {
        // An empty list means "not stated" to the drift evaluation; an empty intersection would widen the delegation.
        RecordedDelegationContextProvider provider = new RecordedDelegationContextProvider(query -> Optional.of(
                new DelegationRecord(null, "alice", "agent-7", null, null, null,
                        List.of("READ"), List.of(), null, null, null, null)));
        CanonicalSecurityContext context = agentContext(CanonicalSecurityContext.Delegation.builder()
                .delegated(true).agentId("agent-7")
                .allowedOperations(new ArrayList<>(List.of("reports.export")))
                .build());

        provider.enrich(event(), context);

        assertThat(context.getDelegation().getAllowedOperations()).containsExactly("READ");
        assertThat(context.getAttributes().get(RecordedDelegationContextProvider.CONFLICTS_ATTRIBUTE))
                .isEqualTo(List.of("allowedOperations"));
    }

    @Test
    void theRecordedObjectiveIsTheDelegationOfRecordAndADifferentStatedOneIsNoted() {
        RecordedDelegationContextProvider provider = new RecordedDelegationContextProvider(query -> Optional.of(record("agent-7")));
        CanonicalSecurityContext context = agentContext(CanonicalSecurityContext.Delegation.builder()
                .delegated(true).agentId("agent-7").objectiveId("payroll-run").build());

        provider.enrich(event(), context);

        assertThat(context.getDelegation().getObjectiveId()).isEqualTo("monthly-report");
        assertThat(context.getAttributes().get(RecordedDelegationContextProvider.CONFLICTS_ATTRIBUTE))
                .isEqualTo(List.of("objectiveId"));
    }

    @Test
    void aRecordForAnotherAgentIsNotApplied() {
        RecordedDelegationContextProvider provider = new RecordedDelegationContextProvider(query -> Optional.of(record("agent-9")));
        CanonicalSecurityContext context = agentContext(CanonicalSecurityContext.Delegation.builder()
                .delegated(true).agentId("agent-7").build());

        provider.enrich(event(), context);

        assertThat(context.getDelegation().getObjectiveId()).isNull();
        assertThat(context.getAttributes()).containsEntry(RecordedDelegationContextProvider.LOOKUP_ATTRIBUTE, "AGENT_MISMATCH");
    }

    @Test
    void noRecordAndAFailedLookupLeaveTheStatedDelegationAsItWas() {
        CanonicalSecurityContext notFound = agentContext(CanonicalSecurityContext.Delegation.builder()
                .delegated(true).agentId("agent-7").build());
        new RecordedDelegationContextProvider(query -> Optional.empty()).enrich(event(), notFound);

        CanonicalSecurityContext failed = agentContext(CanonicalSecurityContext.Delegation.builder()
                .delegated(true).agentId("agent-7").build());
        new RecordedDelegationContextProvider(query -> {
            throw new IllegalStateException("business database unavailable");
        }).enrich(event(), failed);

        assertThat(notFound.getDelegation().getObjectiveId()).isNull();
        assertThat(notFound.getAttributes()).containsEntry(RecordedDelegationContextProvider.LOOKUP_ATTRIBUTE, "NOT_FOUND");
        assertThat(failed.getDelegation().getObjectiveId()).isNull();
        assertThat(failed.getAttributes()).containsEntry(RecordedDelegationContextProvider.LOOKUP_ATTRIBUTE, "FAILED");
    }

    @Test
    void theRecordedDelegationReachesThePromptsDelegationSection() {
        RecordedDelegationContextProvider provider = new RecordedDelegationContextProvider(query -> Optional.of(record("agent-7")));
        DefaultCanonicalSecurityContextProvider contexts = new DefaultCanonicalSecurityContextProvider(
                new InMemoryResourceContextRegistry(), new ContextCoverageEvaluator(),
                List.of(), List.of(), List.of(), List.of(provider), new MetadataObservedScopeInferenceService());
        SecurityEvent event = event();
        event.addMetadata("tenantId", "tenant-acme");
        event.addMetadata("delegated", true);
        event.addMetadata("agentId", "agent-7");

        CanonicalSecurityContext context = contexts.resolve(event).orElseThrow();
        String section = new PromptContextComposer().composeDelegationSection(context);

        assertThat(section)
                .contains("Delegated: true")
                .contains("AgentId: agent-7")
                .contains("ObjectiveId: monthly-report")
                .contains("ObjectiveFamily: REPORTING")
                .contains("AllowedOperations: READ")
                .contains("AllowedResources: SALES_REPORT");
    }

    /** RL-6: the quantity limits the record states reach the context, and the lower of a stated and a recorded one holds. */
    @Test
    void theQuantityLimitsOfTheRecordReachTheContextAndTheLowerHolds() {
        DelegationRecord limited = new DelegationRecord("dlg-42", "alice", "agent-7", "monthly-report", "REPORTING",
                null, List.of("READ", "EXPORT"), List.of("SALES_REPORT"), false, false, null,
                Instant.parse("2026-10-22T09:00:00Z"), "alice", Instant.parse("2026-10-22T02:58:00Z"), 40, 1200);
        CanonicalSecurityContext none = agentContext(CanonicalSecurityContext.Delegation.builder()
                .delegated(true).agentId("agent-7").build());
        CanonicalSecurityContext stricterStated = agentContext(CanonicalSecurityContext.Delegation.builder()
                .delegated(true).agentId("agent-7").maxItemsPerRequest(10).maxItemsTotal(5000).build());
        CanonicalSecurityContext unlimitedRecord = agentContext(CanonicalSecurityContext.Delegation.builder()
                .delegated(true).agentId("agent-7").maxItemsPerRequest(10).build());

        new RecordedDelegationContextProvider(query -> Optional.of(limited)).enrich(event(), none);
        new RecordedDelegationContextProvider(query -> Optional.of(limited)).enrich(event(), stricterStated);
        new RecordedDelegationContextProvider(query -> Optional.of(record("agent-7"))).enrich(event(), unlimitedRecord);

        assertThat(none.getDelegation().getMaxItemsPerRequest()).isEqualTo(40);
        assertThat(none.getDelegation().getMaxItemsTotal()).isEqualTo(1200);
        assertThat(stricterStated.getDelegation().getMaxItemsPerRequest()).isEqualTo(10);
        assertThat(stricterStated.getDelegation().getMaxItemsTotal()).isEqualTo(1200);
        assertThat(unlimitedRecord.getDelegation().getMaxItemsPerRequest()).isEqualTo(10);
        assertThat(unlimitedRecord.getDelegation().getMaxItemsTotal()).isNull();
    }

    /**
     * RL-10: an agent on its own has no delegating person, but its sponsor may have recorded what the agent is for. The
     * record is looked up a second time with the sponsor as the delegator, and it is a standing delegation: the request
     * is still the agent's own, so it is not marked as delegated.
     */
    @Test
    void anAgentOnItsOwnTakesTheStandingDelegationItsSponsorRecorded() {
        List<DelegationRecordQuery> asked = new ArrayList<>();
        RecordedDelegationContextProvider provider = new RecordedDelegationContextProvider(query -> {
            asked.add(query);
            return query.standing() ? Optional.of(standingRecord("agent-7", "sponsor-1")) : Optional.empty();
        });
        CanonicalSecurityContext context = autonomousContext("agent-7", "sponsor-1");

        provider.enrich(event(), context);

        assertThat(asked).containsExactly(
                new DelegationRecordQuery("tenant-acme", "agent-7", "agent-7", null, null, REQUESTED_AT),
                new DelegationRecordQuery("tenant-acme", "sponsor-1", "agent-7", null, null, REQUESTED_AT, true));
        CanonicalSecurityContext.Delegation delegation = context.getDelegation();
        assertThat(delegation.getStanding()).isTrue();
        assertThat(Boolean.TRUE.equals(delegation.getDelegated())).as("the agent still acts on its own").isFalse();
        assertThat(delegation.getObjectiveFamily()).isEqualTo("DATA_EXPORT");
        assertThat(delegation.getAllowedOperations()).containsExactly("EXPORT");
        assertThat(delegation.getMaxItemsPerRequest()).isEqualTo(40);
        assertThat(context.getAttributes())
                .containsEntry(RecordedDelegationContextProvider.LOOKUP_ATTRIBUTE, "FOUND")
                .containsEntry(RecordedDelegationContextProvider.RECORDED_BY_ATTRIBUTE, "sponsor-1");
    }

    @Test
    void aStandingLookupIsNotMadeForADelegatedAgentOrForAnAgentWithoutASponsor() {
        List<DelegationRecordQuery> asked = new ArrayList<>();
        RecordedDelegationContextProvider provider = new RecordedDelegationContextProvider(query -> {
            asked.add(query);
            return Optional.empty();
        });
        CanonicalSecurityContext delegated = autonomousContext("agent-7", "sponsor-1");
        delegated.getAttributes().put("executionSubjectKind", "DELEGATED_AGENT");
        CanonicalSecurityContext noSponsor = autonomousContext("agent-7", null);

        provider.enrich(event(), delegated);
        provider.enrich(event(), noSponsor);

        assertThat(asked).as("one lookup each, as before").hasSize(2).noneMatch(DelegationRecordQuery::standing);
        assertThat(delegated.getDelegation().getStanding()).isNull();
        assertThat(noSponsor.getDelegation().getStanding()).isNull();
    }

    @Test
    void anAgentOnItsOwnWithoutARecordOfItsSponsorLeavesTheContextAsItWas() {
        RecordedDelegationContextProvider provider = new RecordedDelegationContextProvider(query -> Optional.empty());
        CanonicalSecurityContext context = autonomousContext("agent-7", "sponsor-1");

        provider.enrich(event(), context);

        assertThat(context.getDelegation().getStanding()).isNull();
        assertThat(context.getDelegation().getObjectiveFamily()).isNull();
        assertThat(context.getAttributes()).containsEntry(RecordedDelegationContextProvider.LOOKUP_ATTRIBUTE, "NOT_FOUND");
    }

    @Test
    void aStandingRecordForAnotherAgentIsNotApplied() {
        RecordedDelegationContextProvider provider = new RecordedDelegationContextProvider(query ->
                query.standing() ? Optional.of(standingRecord("agent-9", "sponsor-1")) : Optional.empty());
        CanonicalSecurityContext context = autonomousContext("agent-7", "sponsor-1");

        provider.enrich(event(), context);

        assertThat(context.getDelegation().getStanding()).isNull();
        assertThat(context.getAttributes()).containsEntry(RecordedDelegationContextProvider.LOOKUP_ATTRIBUTE,
                "AGENT_MISMATCH");
    }

    private static DelegationRecord standingRecord(String agentId, String sponsorId) {
        return new DelegationRecord("dlg-77", sponsorId, agentId, "weekly-export", "DATA_EXPORT",
                "Export this week's design review packages, 40 documents a day", List.of("EXPORT"), List.of("HX-310"),
                false, false, null, Instant.parse("2026-10-22T09:00:00Z"), sponsorId,
                Instant.parse("2026-10-20T02:58:00Z"), 40, null);
    }

    /** An agent's own request: the subject is the agent, whose registration names its sponsor. */
    private static CanonicalSecurityContext autonomousContext(String agentId, String sponsorId) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("executionSubjectKind", "AUTONOMOUS_AGENT");
        attributes.put("agentId", agentId);
        if (sponsorId != null) {
            attributes.put("agentSponsorId", sponsorId);
        }
        return CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder().userId(agentId).tenantId("tenant-acme").build())
                .delegation(CanonicalSecurityContext.Delegation.builder().agentId(agentId).build())
                .attributes(attributes)
                .build();
    }

    private static DelegationRecord record(String agentId) {
        return new DelegationRecord("dlg-42", "alice", agentId, "monthly-report", "REPORTING",
                "Prepare the October sales report", List.of("READ"), List.of("SALES_REPORT"),
                true, false, null, Instant.parse("2026-10-22T09:00:00Z"));
    }

    private static CanonicalSecurityContext agentContext(CanonicalSecurityContext.Delegation delegation) {
        Map<String, Object> attributes = new HashMap<>();
        return CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder().userId("alice").tenantId("tenant-acme").build())
                .delegation(delegation)
                .attributes(attributes)
                .build();
    }

    private static SecurityEvent event() {
        return SecurityEvent.builder()
                .userId("alice")
                .sessionId("session-1")
                .timestamp(REQUESTED_AT)
                .build();
    }
}
