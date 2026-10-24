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
import io.contexa.contexacommon.security.bridge.AgentConfirmationFacts;
import io.contexa.contexacommon.security.bridge.CredentialFacts;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.agent.AgentConfirmation;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
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
 * Bundle v21.14 (docs/agent F-5, RW-1): an agent's request the accountable person confirmed states that confirmation
 * in a v21 render, right after the credential: who approved it and when, when and why it was asked, that it covers
 * this one request, and its authorization. Its times are told against when the request used the confirmation, not
 * against the request time a host recorded. The inspector draws the line from the sealed context; a v20 render and a
 * request without a confirmation have none.
 */
class V21ConfirmationLineTest {

    private static final PromptInspector INSPECTOR = new PromptInspector(PromptInspector.coreChecks(),
            InspectionGolden.JSON);
    private static final String CASE = "A3";
    private static final String AUTHORIZATION = "ctxa-as:5c1d2e3f";
    /** The confirmation is used 24 days after the request time the host recorded (a demo's company time). */
    private static final long USED_AFTER_REQUEST_SECONDS = 24L * 24 * 3600;

    @Test
    void aConfirmedAgentRequestStatesItsConfirmationAfterItsCredentialInV21Only() {
        InspectionGolden.Render confirmed = render(SecurityDecisionPromptBundles.V21,
                V21ConfirmationLineTest::confirmedAgent);
        List<String> lines = Arrays.asList(confirmed.userPrompt().split("\n"));
        int credential = lines.indexOf(InspectionGolden.lineStarting(confirmed.userPrompt(), "Credential: "));

        assertThat(lines.get(credential + 1)).endsWith("Confirmation: approved by alice 0 min before this request,"
                + " asked 2 min before this request because the delegation had ended, for this request only,"
                + " authorization " + AUTHORIZATION);

        InspectionGolden.Render unconfirmed = render(SecurityDecisionPromptBundles.V21, V21ConfirmationLineTest::agent);
        assertThat(InspectionGolden.hasLine(unconfirmed.userPrompt(), "Confirmation: ")).isFalse();
        InspectionGolden.Render v20 = render(SecurityDecisionPromptBundles.V20, V21ConfirmationLineTest::confirmedAgent);
        assertThat(InspectionGolden.hasLine(v20.userPrompt(), "Confirmation: ")).isFalse();
        // The system text is the same with or without the line: only the dictionary entry is new.
        assertThat(confirmed.systemPrompt()).isEqualTo(unconfirmed.systemPrompt());
    }

    @Test
    void theInspectorComparesTheConfirmationWithTheSealedContext() {
        InspectionGolden.Render confirmed = render(SecurityDecisionPromptBundles.V21,
                V21ConfirmationLineTest::confirmedAgent);

        PromptInspectionResult matched = INSPECTOR.inspect(confirmed.sealed());
        assertThat(matched.findings()).extracting(PromptInspectionFinding::entry).doesNotContain("Confirmation");

        CanonicalSecurityContext other = copy(confirmed.used());
        other.getAttributes().put(AgentConfirmationFacts.AUTHORIZATION_ID, "ctxa-as:another");
        PromptInspectionResult mismatched = INSPECTOR.inspect(new InspectionGolden.Render(confirmed.caseKey(),
                confirmed.profile(), confirmed.systemPrompt(), confirmed.userPrompt(), other,
                confirmed.executionMetadata(), confirmed.ragResultsJson(), confirmed.requestFactsJson()).sealed());
        assertThat(mismatched.verdict()).isEqualTo(PromptInspectionVerdict.FAIL);
        assertThat(mismatched.findings()).filteredOn(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                .extracting(PromptInspectionFinding::entry).contains("Confirmation");
    }

    @Test
    void whatIsNotRecordedIsSaidSoAndTheLineStillMeetsItsDictionaryForm() {
        InspectionGolden.Render bare = render(SecurityDecisionPromptBundles.V21, context -> {
            agent(context);
            context.getAttributes().putAll(AgentConfirmationFacts.of("cfm-2", null, null, null,
                    AgentConfirmation.DECISION_CHALLENGE, null, null));
        });

        assertThat(InspectionGolden.lineStarting(bare.userPrompt(), "Confirmation: ")).endsWith("Confirmation:"
                + " approved by not stated, asked because the decision in force asked for a check, for this request"
                + " only, authorization not recorded");
        assertThat(INSPECTOR.inspect(bare.sealed()).findings()).extracting(PromptInspectionFinding::entry)
                .doesNotContain("Confirmation");
        assertThat(AgentLineValues.confirmation(AgentConfirmationFacts.of("cfm-3", "bob", null, null,
                AgentConfirmation.REQUESTED, "ctxa-as:9", null))).isEqualTo("approved by bob, asked because the agent"
                + " asked for it, for this request only, authorization ctxa-as:9");
        assertThat(AgentLineValues.confirmation(null)).isNull();
        assertThat(AgentLineValues.confirmation(Map.of(AgentConfirmationFacts.DECIDED_BY, "bob"))).isNull();
    }

    /** The golden case as a delegated agent's request with a token. */
    private static void agent(CanonicalSecurityContext context) {
        Instant at = context.getRequestObservedAt();
        Map<String, Object> attributes = context.getAttributes();
        attributes.put("executionSubjectKind", SubjectKind.DELEGATED_AGENT.name());
        attributes.put("agentId", "report-agent");
        attributes.put("delegatorId", "alice");
        attributes.put(CredentialFacts.KIND, CredentialFacts.DELEGATED_TOKEN);
        attributes.put(CredentialFacts.GRANT, CredentialFacts.GRANT_TOKEN_EXCHANGE);
        attributes.put(CredentialFacts.CLIENT_ID, "report-agent-client");
        attributes.put(CredentialFacts.ISSUED_AT, at.minusSeconds(120).toString());
        attributes.put(CredentialFacts.EXPIRES_AT, at.plusSeconds(1680).toString());
    }

    /** That request after its delegating person approved it: asked 150 s and approved 20 s before it used it. */
    private static void confirmedAgent(CanonicalSecurityContext context) {
        agent(context);
        Instant used = context.getRequestObservedAt().plusSeconds(USED_AFTER_REQUEST_SECONDS);
        context.getAttributes().putAll(AgentConfirmationFacts.of("cfm-1", "alice", used.minusSeconds(20),
                used.minusSeconds(150), AgentConfirmation.DELEGATION_ENDED, AUTHORIZATION, used));
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
