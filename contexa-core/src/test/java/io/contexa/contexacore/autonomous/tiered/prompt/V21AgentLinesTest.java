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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacommon.security.bridge.CredentialFacts;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.baseline.AgentBaselineView;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.enricher.RecordedDelegationContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.RecordsHolder;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageLevel;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageReport;
import io.contexa.contexacore.autonomous.event.support.InvocationArguments;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Bundle v21.9 (docs/agent A2-4 to A2-11): a delegated agent's request is drawn by the v21 dictionary with the agent
 * named apart from the account, the token, the delegation by its fields, the agent's session so far and who wrote the
 * records; its objective text and call arguments are untrusted texts; a delegation the records completed is not named
 * missing. The inspector compares every such line with the sealed context. The v20 render stays as it was.
 */
class V21AgentLinesTest {

    private static final PromptInspector INSPECTOR = new PromptInspector(PromptInspector.coreChecks(),
            InspectionGolden.JSON);
    private static final String CASE = "A3";
    private static final String OBJECTIVE = "Prepare the weekly HX-310 drawing report";
    private static final String DELEGATION_MISSING = "Bridge missing context: DELEGATION.";

    @Test
    void aV21RenderDrawsTheAgentLinesAndAV20RenderDoesNot() {
        InspectionGolden.Render agent = render(SecurityDecisionPromptBundles.V21, V21AgentLinesTest::delegatedAgent);
        String user = agent.used().getActor().getUserId();
        List<String> lines = Arrays.asList(agent.userPrompt().split("\n"));
        int subject = lines.indexOf(InspectionGolden.lineStarting(agent.userPrompt(), "Subject: "));

        assertThat(lines.get(subject)).contains("Subject: " + user + " (HUMAN_USER, ")
                .endsWith(", through agent report-agent, agent sponsor bob, agent registration ACTIVE)");
        assertThat(lines.get(subject + 1)).endsWith("Credential: delegated access token, grant token-exchange, client"
                + " report-agent-client, issued 2 min before this request, expires 28 min after this request, actor"
                + " chain depth 1, not bound to a key");
        assertThat(InspectionGolden.lineStarting(agent.userPrompt(), "Delegation: ")).endsWith("Delegation: agent"
                + " report-agent for " + user + ", chain depth 1, objective REPORTING, allowed READ on PROJECT_DOCUMENTS,"
                + " expires 3 h after this request, proof signed token claim and delegation record, drift no (Current"
                + " action family is listed in delegated action scope evidence)");
        assertThat(InspectionGolden.lineStarting(agent.userPrompt(), "DelegationActivity: ")).endsWith(
                "DelegationActivity: 1 earlier request in this agent session (READ 1), 0 items exported, 1 distinct"
                        + " target, 0 refused, first 5 min before this request, order READ (last 1), median 5 min"
                        + " between requests");
        assertThat(InspectionGolden.lineStarting(agent.userPrompt(), "RecordProvenance: ")).endsWith(
                "RecordProvenance: delegation DLG-1 recorded by " + user + " (the delegator) 1 h before this"
                        + " request");
        assertThat(agent.userPrompt()).contains("source=" + UntrustedTextSources.DELEGATION_OBJECTIVE + "; \""
                + OBJECTIVE + "\"").contains("source=" + UntrustedTextSources.CALL_ARGUMENTS + "; \"projectKey=HX-310\"");
        assertThat(InspectionGolden.lineStarting(agent.userPrompt(), "Delegation: ")).doesNotContain(OBJECTIVE);
        assertThat(InspectionGolden.lineStarting(agent.userPrompt(), "Coverage: ")).doesNotContain(DELEGATION_MISSING)
                .doesNotContain("If delegated agents are used").doesNotContain("any ALLOW conclusion");

        InspectionGolden.Render v20 = render(SecurityDecisionPromptBundles.V20, V21AgentLinesTest::delegatedAgent);
        assertThat(InspectionGolden.lineStarting(v20.userPrompt(), "Subject: ")).doesNotContain("through agent");
        assertThat(InspectionGolden.hasLine(v20.userPrompt(), "Credential: ")).isFalse();
        assertThat(InspectionGolden.hasLine(v20.userPrompt(), "DelegationActivity: ")).isFalse();
        assertThat(InspectionGolden.hasLine(v20.userPrompt(), "RecordProvenance: ")).isFalse();
        // The delegated request's subject is the person: its records are the person's own, with no holder line.
        assertThat(InspectionGolden.hasLine(agent.userPrompt(), "RecordsHolder: ")).isFalse();
        assertThat(v20.userPrompt()).doesNotContain("source=" + UntrustedTextSources.CALL_ARGUMENTS)
                .doesNotContain("source=" + UntrustedTextSources.DELEGATION_OBJECTIVE);
        assertThat(InspectionGolden.lineStarting(v20.userPrompt(), "Coverage: ")).contains(DELEGATION_MISSING);
    }

    @Test
    void anAgentOnItsOwnIsNamedByItsRegistrationWithItsClient() {
        InspectionGolden.Render alone = render(SecurityDecisionPromptBundles.V21, context -> {
            context.getAttributes().put("executionSubjectKind", SubjectKind.AUTONOMOUS_AGENT.name());
            context.getAttributes().put("agentId", "report-agent");
            context.getAttributes().put("agentSponsorId", "bob");
            context.getAttributes().put("agentRegistrationStatus", "ACTIVE");
            context.setDelegation(CanonicalSecurityContext.Delegation.builder().delegated(false)
                    .agentId("report-agent").build());
            new RecordsHolder("bob", RecordsHolder.SPONSOR).stateOn(context);
            context.setCoverage(new ContextCoverageReport(ContextCoverageLevel.IDENTITY_AWARE, List.of(),
                    List.of("Delegated objective family is unavailable.", "Session MFA state is unavailable."),
                    List.of(), List.of("Delegated objective family is missing; "
                    + "delegated-agent intent should remain conservative."), null));
        });
        String user = alone.used().getActor().getUserId();

        assertThat(InspectionGolden.lineStarting(alone.userPrompt(), "Subject: ")).contains("Subject: report-agent"
                + " (AGENT_RUNTIME, ").endsWith(", client " + user + ", sponsor bob, registration ACTIVE)");
        // A2-12: its company records are its sponsor's, and a line before the policy line says so.
        List<String> lines = Arrays.asList(alone.userPrompt().split("\n"));
        int holder = lines.indexOf(InspectionGolden.lineStarting(alone.userPrompt(), "RecordsHolder: "));
        assertThat(lines.get(holder)).endsWith("RecordsHolder: bob (the agent's sponsor)");
        assertThat(lines.get(holder + 1)).contains("Policy: ");
        assertThat(INSPECTOR.inspect(alone.sealed()).findings()).extracting(PromptInspectionFinding::entry)
                .doesNotContain("RecordsHolder");
        // An agent on its own has no delegation: the coverage states no delegated objective missing (A2-6).
        assertThat(InspectionGolden.lineStarting(alone.userPrompt(), "Coverage: ")).doesNotContain("Delegated objective")
                .contains("missing Session MFA state is unavailable.");
        assertThat(INSPECTOR.inspect(alone.sealed()).findings())
                .filteredOn(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH).isEmpty();
    }

    /**
     * v21.12 (docs/agent A4-3, A4-1, A4-6): an agent's baseline lines name whose they are, its usual order of operations
     * and its clients; the inspector compares each with the sealed context, and a person's render has none of them.
     */
    @Test
    void anAgentsBaselineLinesAreDrawnAndComparedAndAPersonsRenderHasNone() {
        AgentBaselineView view = AgentBaselineView.calculate(List.of(
                new AgentBaselineView.Facts("report-agent-client", "1a2b3c4d5e6f7a8b", null, "READ"),
                new AgentBaselineView.Facts("report-agent-client", "1a2b3c4d5e6f7a8b", "READ", "READ")),
                new AgentBaselineView.Facts("report-agent-client", "1a2b3c4d5e6f7a8b", "READ", "EXPORT"));
        InspectionGolden.Render agent = render(SecurityDecisionPromptBundles.V21, context -> {
            delegatedAgent(context);
            CanonicalSecurityContext.WorkProfile profile = context.getWorkProfile() != null ? context.getWorkProfile()
                    : new CanonicalSecurityContext.WorkProfile();
            profile.setAgentBaseline(view);
            context.setWorkProfile(profile);
        });
        String user = agent.used().getActor().getUserId();

        assertThat(InspectionGolden.lineStarting(agent.userPrompt(), "BaselineSubject: ")).endsWith(
                "BaselineSubject: agent report-agent acting for " + user + ", learned from this agent's own requests");
        assertThat(InspectionGolden.lineStarting(agent.userPrompt(), "UsualSequence: ")).endsWith(
                "UsualSequence: READ>READ 1; this request READ>EXPORT seen 0 times before");
        assertThat(InspectionGolden.lineStarting(agent.userPrompt(), "UsualClients: ")).endsWith(
                "UsualClients: report-agent-client #1a2b3c4d5e6f7a8b 2; this request report-agent-client"
                        + " #1a2b3c4d5e6f7a8b seen 2 times before");
        assertThat(INSPECTOR.inspect(agent.sealed()).findings())
                .filteredOn(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH).isEmpty();
        assertThat(INSPECTOR.inspect(agent.sealed()).findings()).extracting(PromptInspectionFinding::entry)
                .doesNotContain("BaselineSubject", "UsualSequence", "UsualClients");

        InspectionGolden.Render person = render(SecurityDecisionPromptBundles.V21, context -> { });
        assertThat(InspectionGolden.hasLine(person.userPrompt(), "BaselineSubject: ")).isFalse();
        assertThat(InspectionGolden.hasLine(person.userPrompt(), "UsualSequence: ")).isFalse();
        assertThat(InspectionGolden.hasLine(person.userPrompt(), "UsualClients: ")).isFalse();
    }

    /**
     * docs/agent A4-4: the v19 and v20 system texts leave the automation client boundary out for an agent's request
     * only; the v21 text has none and is the same for both.
     */
    @Test
    void anAgentsRequestIsJudgedWithoutTheAutomationClientBoundary() {
        String v19Person = render(SecurityDecisionPromptBundles.DEFAULT, context -> { }).systemPrompt();
        String v19Agent = render(SecurityDecisionPromptBundles.DEFAULT, V21AgentLinesTest::delegatedAgent).systemPrompt();
        assertThat(v19Person).contains("BotUserAgent=true");
        assertThat(v19Agent).doesNotContain("BotUserAgent=true")
                .isEqualTo(v19Person.replace(SecurityDecisionPromptSections.V19_AUTOMATION_BOUNDARY, ""));

        String v20Person = render(SecurityDecisionPromptBundles.V20, context -> { }).systemPrompt();
        String v20Agent = render(SecurityDecisionPromptBundles.V20, V21AgentLinesTest::delegatedAgent).systemPrompt();
        assertThat(v20Person).contains("automation or transport anomalies (ClientSignals)").contains("a bot UA");
        assertThat(v20Agent).doesNotContain("automation or transport anomalies").doesNotContain("a bot UA")
                .contains("a device that does not match (Device), or impossible travel");

        assertThat(render(SecurityDecisionPromptBundles.V21, V21AgentLinesTest::delegatedAgent).systemPrompt())
                .isEqualTo(render(SecurityDecisionPromptBundles.V21, context -> { }).systemPrompt());
    }

    @Test
    void theInspectorComparesEveryAgentLineWithTheSealedContext() {
        InspectionGolden.Render agent = render(SecurityDecisionPromptBundles.V21, V21AgentLinesTest::delegatedAgent);

        PromptInspectionResult matched = INSPECTOR.inspect(agent.sealed());
        assertThat(matched.verdict()).isIn(PromptInspectionVerdict.PASS, PromptInspectionVerdict.INCOMPLETE);
        assertThat(matched.findings()).extracting(PromptInspectionFinding::entry)
                .doesNotContain("Subject", "Credential", "Delegation", "DelegationActivity", "RecordProvenance",
                        "Coverage");
        assertThat(matched.findings()).filteredOn(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                .isEmpty();

        CanonicalSecurityContext other = copy(agent.used());
        other.getAttributes().put(CredentialFacts.CLIENT_ID, "another-client");
        other.getDelegation().setAgentId("another-agent");
        other.getAttributes().put(InvocationArguments.KEY, "projectKey=GB-500");
        PromptInspectionResult mismatched = INSPECTOR.inspect(new InspectionGolden.Render(agent.caseKey(),
                agent.profile(), agent.systemPrompt(), agent.userPrompt(), other, agent.executionMetadata(),
                agent.ragResultsJson(), agent.requestFactsJson()).sealed());
        assertThat(mismatched.verdict()).isEqualTo(PromptInspectionVerdict.FAIL);
        List<PromptInspectionFinding> mismatches = mismatched.findings().stream()
                .filter(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH).toList();
        assertThat(mismatches).extracting(PromptInspectionFinding::entry).contains("Credential", "Delegation");
        assertThat(mismatches).anyMatch(finding -> finding.actual() != null
                && finding.actual().contains(UntrustedTextSources.CALL_ARGUMENTS));
    }

    /** The golden case as a delegated agent's request: the publisher's agent facts, its token, delegation and records. */
    private static void delegatedAgent(CanonicalSecurityContext context) {
        Instant at = context.getRequestObservedAt();
        String user = context.getActor().getUserId();
        Map<String, Object> attributes = context.getAttributes();
        attributes.put("executionSubjectKind", SubjectKind.DELEGATED_AGENT.name());
        attributes.put("agentId", "report-agent");
        attributes.put("delegatorId", user);
        attributes.put("delegationChainDepth", 1);
        attributes.put("delegationEvidenceState", "SIGNED_TOKEN_CLAIM");
        attributes.put("agentSponsorId", "bob");
        attributes.put("agentRegistrationStatus", "ACTIVE");
        attributes.put(RecordedDelegationContextProvider.LOOKUP_ATTRIBUTE, "FOUND");
        attributes.put(RecordedDelegationContextProvider.RECORD_ID_ATTRIBUTE, "DLG-1");
        attributes.put(RecordedDelegationContextProvider.RECORDED_BY_ATTRIBUTE, user);
        attributes.put(RecordedDelegationContextProvider.RECORDED_AT_ATTRIBUTE, at.minusSeconds(3600).toString());
        attributes.put(CredentialFacts.KIND, CredentialFacts.DELEGATED_TOKEN);
        attributes.put(CredentialFacts.GRANT, CredentialFacts.GRANT_TOKEN_EXCHANGE);
        attributes.put(CredentialFacts.CLIENT_ID, "report-agent-client");
        attributes.put(CredentialFacts.ISSUED_AT, at.minusSeconds(120).toString());
        attributes.put(CredentialFacts.EXPIRES_AT, at.plusSeconds(1680).toString());
        attributes.put(CredentialFacts.CHAIN_DEPTH, 1);
        attributes.put(InvocationArguments.KEY, "projectKey=HX-310");
        context.setDelegation(CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .agentId("report-agent")
                .objectiveFamily("REPORTING")
                .objectiveSummary(OBJECTIVE)
                .allowedOperations(List.of("READ"))
                .allowedResources(List.of("PROJECT_DOCUMENTS"))
                .expiresAt(at.plusSeconds(3 * 3600).toString())
                .objectiveDrift(false)
                .objectiveDriftSummary("Delegated objective comparison evidence is available. | Objective summary: "
                        + OBJECTIVE + " | Current action family is listed in delegated action scope evidence.")
                .build());
        CanonicalSecurityContext.SessionNarrativeProfile narrative = context.getSessionNarrativeProfile() != null
                ? context.getSessionNarrativeProfile() : new CanonicalSecurityContext.SessionNarrativeProfile();
        narrative.setSessionDecisions(List.of(new SessionDecisionRecord(at.minusSeconds(300), "GET",
                "/api/documents/HX-310-DWG-1", null, "READ", "ALLOW", "HX-310-DWG-1", null)));
        context.setSessionNarrativeProfile(narrative);
        ContextCoverageReport coverage = context.getCoverage();
        context.setCoverage(new ContextCoverageReport(
                coverage != null ? coverage.level() : ContextCoverageLevel.IDENTITY_AWARE,
                coverage != null ? coverage.availableFacts() : List.of(),
                List.of(DELEGATION_MISSING),
                coverage != null ? coverage.remediationHints() : List.of(),
                coverage != null ? coverage.confidenceWarnings() : List.of(),
                coverage != null ? coverage.summary() : null));
    }

    /** The L1 render of the golden case by the given bundle after a change to its sealed context. */
    private static InspectionGolden.Render render(SecurityDecisionPromptBundles.Bundle bundle,
                                                  Consumer<CanonicalSecurityContext> change) {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        JsonNode goldenCase = golden.cases().stream().filter(node -> CASE.equals(node.path("caseKey").asText()))
                .findFirst().orElseThrow();
        CanonicalSecurityContext context = InspectionGolden.SERIALIZER
                .deserialize(goldenCase.path("canonicalContext").toString());
        change.accept(context);
        ObjectNode changed = goldenCase.deepCopy();
        try {
            changed.set("canonicalContext", InspectionGolden.JSON.readTree(InspectionGolden.SERIALIZER.serialize(context)));
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(bundle.version());
        SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(changed,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties);
        return new InspectionGolden.Render(rendered.caseKey(), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT,
                rendered.systemText(), rendered.userText(), rendered.canonicalContext(),
                rendered.executionMetadata().toMetadataMap(), goldenCase.path("ragResults").toString(),
                goldenCase.path("requestFacts").toString());
    }

    private static CanonicalSecurityContext copy(CanonicalSecurityContext context) {
        return InspectionGolden.SERIALIZER.deserialize(InspectionGolden.SERIALIZER.serialize(context));
    }
}
