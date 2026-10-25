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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacommon.security.bridge.CredentialFacts;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.baseline.AgentBaselineView;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.enricher.RecordedDelegationContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.RecordsHolder;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The v21 agent lines (docs/agent A2-4, A2-6, A2-9, A2-10, A2-11) state records and comparisons only. */
class AgentLineValuesTest {

    private static final Instant AT = Instant.parse("2026-10-23T09:00:00Z");

    @Test
    void aTokenStatesItsKindGrantClientLifeActorChainAndBinding() {
        Map<String, Object> delegated = new LinkedHashMap<>();
        delegated.put(CredentialFacts.KIND, CredentialFacts.DELEGATED_TOKEN);
        delegated.put(CredentialFacts.GRANT, CredentialFacts.GRANT_TOKEN_EXCHANGE);
        delegated.put(CredentialFacts.CLIENT_ID, "report-agent-client");
        delegated.put(CredentialFacts.ISSUED_AT, "2026-10-23T08:58:00Z");
        delegated.put(CredentialFacts.EXPIRES_AT, "2026-10-23T09:28:00Z");
        delegated.put(CredentialFacts.CHAIN_DEPTH, 2);
        delegated.put(CredentialFacts.PRIOR_ACTORS, List.of("planner-agent"));
        Map<String, Object> client = Map.of(CredentialFacts.KIND, CredentialFacts.CLIENT_TOKEN,
                CredentialFacts.BINDING, CredentialFacts.BINDING_DPOP);

        assertThat(AgentLineValues.credential(delegated, AT)).isEqualTo("delegated access token, grant token-exchange,"
                + " client report-agent-client, issued 2 min before this request, expires 28 min after this request,"
                + " actor chain depth 2 (before it: planner-agent), not bound to a key");
        assertThat(AgentLineValues.credential(client, AT)).isEqualTo("client's own access token, bound to a DPoP key");
        // A host may state a request time on its own clock (a company clock weeks apart): the token's times are told
        // against when the resource server read the token, on the issuer's clock.
        delegated.put(CredentialFacts.CHECKED_AT, "2026-10-23T08:59:00Z");
        assertThat(AgentLineValues.credential(delegated, Instant.parse("2026-09-30T14:20:00Z")))
                .contains("issued 1 min before this request, expires 29 min after this request");
        assertThat(AgentLineValues.credential(Map.of("sessionId", "S-1"), AT)).isNull();
    }

    @Test
    void aDelegationStatesItsFieldsAndTheComparisonOutcomesButNotItsObjectiveText() {
        CanonicalSecurityContext context = delegated();

        String line = AgentLineValues.delegation(context, AT);

        assertThat(line).isEqualTo("agent report-agent for alice, chain depth 1, objective REPORTING, allowed READ/EXPORT"
                + " on PROJECT_DOCUMENTS/HX-310, expires 3 h after this request, proof signed token claim and delegation"
                + " record, drift no (Current action family is listed in delegated action scope evidence; Current resource"
                + " matches delegated raw resource constraints)");
        assertThat(line).doesNotContain("Prepare the weekly");
        assertThat(AgentLineValues.delegationObjective(context)).isEqualTo("Prepare the weekly HX-310 drawing report");
    }

    /** RL-6: a delegation that states quantity limits says them in its line; one that states none reads as before. */
    @Test
    void aDelegationStatesTheQuantityLimitsItStates() {
        CanonicalSecurityContext both = delegated();
        both.getDelegation().setMaxItemsPerRequest(40);
        both.getDelegation().setMaxItemsTotal(1200);
        CanonicalSecurityContext perRequest = delegated();
        perRequest.getDelegation().setMaxItemsPerRequest(40);
        CanonicalSecurityContext total = delegated();
        total.getDelegation().setMaxItemsTotal(60);

        assertThat(AgentLineValues.delegation(both, AT)).contains(", expires 3 h after this request, limits 40 items per"
                + " request and 1,200 items in the session, proof signed token claim");
        assertThat(AgentLineValues.delegation(perRequest, AT)).contains("limits 40 items per request, proof")
                .doesNotContain("in the session");
        assertThat(AgentLineValues.delegation(total, AT)).contains("limits 60 items in the session, proof")
                .doesNotContain("per request");
        assertThat(AgentLineValues.delegation(delegated(), AT)).doesNotContain("limits");
    }

    @Test
    void anAgentSessionStatesWhatItDidSoFarAndAPersonsSessionStatesNothing() {
        CanonicalSecurityContext context = delegated();
        context.setSessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder()
                .sessionDecisions(List.of(
                        new SessionDecisionRecord(AT.minusSeconds(720), "GET", "/api/documents/HX-310-DWG-1", null,
                                "READ", "ALLOW", "HX-310-DWG-1", null),
                        new SessionDecisionRecord(AT.minusSeconds(600), "POST", "/api/projects/HX-310/exports", null,
                                "EXPORT", "ALLOW", "HX-310", 1240),
                        new SessionDecisionRecord(AT.minusSeconds(300), "POST", "/api/projects/GB-500/exports", null,
                                "EXPORT", SessionDecisionRecord.AUTHORIZATION_DENIED, "GB-500", 4000)))
                .build());
        CanonicalSecurityContext person = CanonicalSecurityContext.builder()
                .sessionNarrativeProfile(context.getSessionNarrativeProfile()).build();

        assertThat(AgentLineValues.delegationActivity(context, AT)).isEqualTo("3 earlier requests in this agent session"
                + " (READ 1, EXPORT 2), 1,240 items exported, 3 distinct targets, 1 refused, first 12 min before this"
                + " request, order READ, EXPORT x2 (last 3), median 5 min between requests");
        assertThat(AgentLineValues.delegationActivity(person, AT)).isNull();
    }

    /** docs/agent A4-5: the order of the session's latest requests and the median time between them. */
    @Test
    void anAgentSessionStatesTheOrderOfItsLatestRequestsAndTheirPace() {
        List<SessionDecisionRecord> burst = new ArrayList<>();
        burst.add(new SessionDecisionRecord(AT.minusSeconds(40), "GET", "/api/projects/HX-310/documents", null,
                "LIST", "ALLOW", "HX-310", null));
        for (int index = 0; index < 12; index++) {
            burst.add(new SessionDecisionRecord(AT.minusSeconds(38 - 2L * index), "GET", "/api/customers/C-" + index,
                    null, "READ", "ALLOW", "C-" + index, null));
        }

        assertThat(AgentLineValues.order(burst)).as("the last ten, the run of reads as one").isEqualTo("READ x10 (last 10)");
        assertThat(AgentLineValues.order(burst.subList(0, 4))).isEqualTo("LIST, READ x3 (last 4)");
        assertThat(AgentLineValues.medianInterval(burst, AT)).isEqualTo("2 s between requests");
        assertThat(AgentLineValues.medianInterval(List.of(), AT)).isNull();
        assertThat(AgentLineValues.order(List.of())).isNull();
    }

    /** docs/agent A4-3, A4-1, A4-6: whose baseline an agent's lines state, its usual order and its clients. */
    @Test
    void anAgentsBaselineLinesNameWhoseTheyAreItsUsualOrderAndItsClients() {
        CanonicalSecurityContext context = delegated();
        AgentBaselineView view = AgentBaselineView.calculate(List.of(
                new AgentBaselineView.Facts("report-client", "1a2b3c4d5e6f7a8b", null, "LIST"),
                new AgentBaselineView.Facts("report-client", "1a2b3c4d5e6f7a8b", "LIST", "READ"),
                new AgentBaselineView.Facts("report-client", "1a2b3c4d5e6f7a8b", "READ", "READ")),
                new AgentBaselineView.Facts("other-client", "9f9f9f9f9f9f9f9f", "READ", "EXPORT"));
        context.setWorkProfile(CanonicalSecurityContext.WorkProfile.builder().agentBaseline(view).build());

        assertThat(AgentLineValues.baselineSubject(context))
                .isEqualTo("agent report-agent acting for alice, learned from this agent's own requests");
        assertThat(AgentLineValues.usualSequence(context))
                .isEqualTo("LIST>READ 1, READ>READ 1; this request READ>EXPORT seen 0 times before");
        assertThat(AgentLineValues.usualClients(context)).isEqualTo("report-client #1a2b3c4d5e6f7a8b 3; this request"
                + " other-client #9f9f9f9f9f9f9f9f seen 0 times before");

        CanonicalSecurityContext person = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder().userId("alice").build())
                .workProfile(CanonicalSecurityContext.WorkProfile.builder().agentBaseline(view).build()).build();
        assertThat(AgentLineValues.baselineSubject(person)).isNull();
        assertThat(AgentLineValues.usualSequence(person)).isNull();
        assertThat(AgentLineValues.usualClients(person)).isNull();

        // An agent on its own (its client's token or its own account) learns and is named alone.
        CanonicalSecurityContext alone = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder().userId("report-client").build())
                .attributes(new LinkedHashMap<>(Map.of("executionSubjectKind", SubjectKind.AUTONOMOUS_AGENT.name(),
                        "agentId", "report-agent")))
                .workProfile(CanonicalSecurityContext.WorkProfile.builder().agentBaseline(view).build()).build();
        assertThat(AgentLineValues.baselineSubject(alone))
                .isEqualTo("agent report-agent on its own, learned from this agent's own requests");
        assertThat(AgentLineValues.usualClients(alone)).isEqualTo(AgentLineValues.usualClients(context));

        context.setWorkProfile(CanonicalSecurityContext.WorkProfile.builder()
                .agentBaseline(AgentBaselineView.calculate(List.of(), null)).build());
        assertThat(AgentLineValues.usualSequence(context)).as("nothing learned yet").isNull();
        assertThat(AgentLineValues.baselineSubject(context)).isNotNull();
    }

    @Test
    void aRecordStatesWhoWroteItAndWhenWithTheAuthorsRelationToTheRequest() {
        CanonicalSecurityContext context = delegated();
        context.setFrictionProfile(CanonicalSecurityContext.FrictionProfile.builder()
                .approvalRecords(List.of(CanonicalSecurityContext.ApprovalRecord.builder().approvalId("APR-1")
                        .recordedBy("report-agent").recordedAt(AT.minusSeconds(120)).build(),
                        CanonicalSecurityContext.ApprovalRecord.builder().approvalId("APR-2").build()))
                .build());
        context.getAttributes().put(RecordedDelegationContextProvider.RECORD_ID_ATTRIBUTE, "DLG-1");
        context.getAttributes().put(RecordedDelegationContextProvider.RECORDED_BY_ATTRIBUTE, "alice");
        context.getAttributes().put(RecordedDelegationContextProvider.RECORDED_AT_ATTRIBUTE, "2026-10-23T08:00:00Z");

        assertThat(AgentLineValues.recordProvenance(context, AT)).isEqualTo("approval APR-1 recorded by report-agent"
                + " (this request's agent) 2 min before this request; delegation DLG-1 recorded by alice (the"
                + " delegator) 1 h before this request");
        assertThat(AgentLineValues.recordProvenance(CanonicalSecurityContext.builder().build(), AT)).isNull();
    }

    @Test
    void theCoverageStatesTheDelegationAsTheDelegationLineDoesAndAWarningKeepsItsFactOnly() {
        CanonicalSecurityContext context = delegated();
        CanonicalSecurityContext incomplete = delegated();
        incomplete.getDelegation().setAllowedOperations(List.of());
        incomplete.getDelegation().setAllowedResources(List.of());
        CanonicalSecurityContext alone = CanonicalSecurityContext.builder()
                .delegation(CanonicalSecurityContext.Delegation.builder().delegated(false).agentId("report-agent").build())
                .build();
        String hint = "If delegated agents are used, propagate agent identity, objective, and allowed scope metadata for"
                + " the current request.";

        assertThat(AgentLineValues.delegationComplete(context)).isTrue();
        assertThat(AgentLineValues.keepsCoverageFact("Bridge missing context: DELEGATION.", context)).isFalse();
        assertThat(AgentLineValues.keepsCoverageFact("Bridge missing context: DELEGATION.", incomplete)).isTrue();
        assertThat(AgentLineValues.keepsHint(hint, context)).isFalse();
        assertThat(AgentLineValues.keepsHint(hint, incomplete)).isTrue();
        // An agent on its own has no delegation: what the report says of a delegated objective is not its fact.
        assertThat(AgentLineValues.keepsCoverageFact("Delegated objective family is unavailable.", alone)).isFalse();
        assertThat(AgentLineValues.keepsCoverageFact("Delegated objective family is unavailable.", incomplete)).isTrue();
        assertThat(AgentLineValues.keepsCoverageFact("Session MFA state is unavailable.", alone)).isTrue();
        assertThat(AgentLineValues.warningFact("Delegated objective comparison shows a mismatch between current request"
                + " facts and declared delegated scope; any ALLOW conclusion must explain why the request is still"
                + " acceptable.")).isEqualTo("Delegated objective comparison shows a mismatch between current request"
                + " facts and declared delegated scope.");
    }

    /** A2-12: the records' holder is stated only when it is another person than the request's subject. */
    @Test
    void theRecordsHolderIsStatedWhenItIsAnotherPersonThanTheSubject() {
        CanonicalSecurityContext sponsor = CanonicalSecurityContext.builder().build();
        new RecordsHolder("bob", RecordsHolder.SPONSOR).stateOn(sponsor);
        CanonicalSecurityContext delegator = CanonicalSecurityContext.builder().build();
        new RecordsHolder("alice", RecordsHolder.DELEGATOR).stateOn(delegator);
        CanonicalSecurityContext subject = CanonicalSecurityContext.builder().build();
        new RecordsHolder("alice", RecordsHolder.SUBJECT).stateOn(subject);

        assertThat(AgentLineValues.recordsHolder(sponsor)).isEqualTo("bob (the agent's sponsor)");
        assertThat(AgentLineValues.recordsHolder(delegator)).isEqualTo("alice (the delegator)");
        assertThat(AgentLineValues.recordsHolder(subject)).isNull();
        assertThat(AgentLineValues.recordsHolder(CanonicalSecurityContext.builder().build())).isNull();
    }

    @Test
    void theAgentIsNamedByThePublishersSubjectKind() {
        CanonicalSecurityContext alone = CanonicalSecurityContext.builder()
                .attributes(new LinkedHashMap<>(Map.of("executionSubjectKind", SubjectKind.AUTONOMOUS_AGENT.name(),
                        "agentId", "report-agent", "agentSponsorId", "bob", "agentRegistrationStatus", "ACTIVE")))
                .build();

        assertThat(AgentLineValues.agent(alone))
                .isEqualTo(new AgentLineValues.Agent("report-agent", false, "bob", "ACTIVE"));
        assertThat(AgentLineValues.agent(delegated()).delegated()).isTrue();
        assertThat(AgentLineValues.agent(CanonicalSecurityContext.builder().build())).isNull();
    }

    private static CanonicalSecurityContext delegated() {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("executionSubjectKind", SubjectKind.DELEGATED_AGENT.name());
        attributes.put("agentId", "report-agent");
        attributes.put("delegatorId", "alice");
        attributes.put("delegationChainDepth", 1);
        attributes.put("delegationEvidenceState", "SIGNED_TOKEN_CLAIM");
        attributes.put(RecordedDelegationContextProvider.LOOKUP_ATTRIBUTE, "FOUND");
        return CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder().userId("alice").build())
                .delegation(CanonicalSecurityContext.Delegation.builder()
                        .delegated(true)
                        .agentId("report-agent")
                        .objectiveFamily("REPORTING")
                        .objectiveSummary("Prepare the weekly HX-310 drawing report")
                        .allowedOperations(List.of("READ", "EXPORT"))
                        .allowedResources(List.of("PROJECT_DOCUMENTS", "HX-310"))
                        .expiresAt("2026-10-23T12:00:00Z")
                        .objectiveDrift(false)
                        .objectiveDriftSummary("Delegated objective comparison evidence is available. | Objective family:"
                                + " REPORTING | Objective summary: Prepare the weekly HX-310 drawing report | Current"
                                + " action family: READ | Current action family is listed in delegated action scope"
                                + " evidence. | Current resource matches delegated raw resource constraints.")
                        .build())
                .attributes(attributes)
                .build();
    }
}
