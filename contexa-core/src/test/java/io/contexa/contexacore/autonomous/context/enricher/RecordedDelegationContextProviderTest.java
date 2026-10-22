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
