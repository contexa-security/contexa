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
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * v1.0 (plan 2.2, 2.8, 2.9): the v1.0 dictionary is the v21 dictionary with the facts of v19 and v20 the v21 lines did
 * not state, each in its place; its values fit their forms; the v1.0 system text is the v21 judgment with the reading
 * and honesty sentences of v19 and v20, and the decision rules only in the variants that have them.
 */
class SecurityDecisionV1BundleTest {

    /** Each v1.0 entry and the v21 entry it comes right after. */
    private static final Map<String, String> PLACES = Map.ofEntries(
            Map.entry("REQUEST.TargetType", "REQUEST.TargetScope"),
            Map.entry("REQUEST.NetworkZone", "REQUEST.Network"),
            Map.entry("SESSION.BurstPattern", "SESSION.RecentRequests"),
            Map.entry("SESSION.HostDecisionCounts", "SESSION.RequestsInSession"),
            Map.entry("DECISION_FACTS.SeenCombination", "DECISION_FACTS.SameAsBaseline"),
            Map.entry("DECISION_FACTS.RecordsLookedUp", "DECISION_FACTS.Policy"),
            Map.entry("DECISION_FACTS.ScopeDenied", "DECISION_FACTS.RoleScope"),
            Map.entry("DECISION_FACTS.ScopeHabits", "DECISION_FACTS.ScopeDenied"),
            Map.entry("DECISION_FACTS.TenantMatch", "DECISION_FACTS.DataConflicts"),
            Map.entry("DECISION_FACTS.VerifiedSignal", "DECISION_FACTS.ClientSignals"),
            Map.entry("DECISION_FACTS.CohortBands", "DECISION_FACTS.PeerCohort"),
            Map.entry("DECISION_FACTS.DelegationControls", "DECISION_FACTS.ArgumentOrigin"),
            Map.entry("PAST_RECORDS.PastRecordsPermission", "PAST_RECORDS.PastRecordsState"),
            Map.entry("PAST_RECORDS.SimilarCase{i}", "PAST_RECORDS.PastRecord{i}"));

    @Test
    void theV1DictionaryIsTheV21DictionaryWithEachAddedFactInItsPlace() {
        List<String> v21 = keys(SecurityDecisionPromptDictionary.V21_ENTRIES);
        List<String> v1 = keys(SecurityDecisionPromptDictionary.V1_ENTRIES);

        assertThat(v1).hasSize(v21.size() + PLACES.size());
        assertThat(v1.stream().filter(v21::contains).toList()).containsExactlyElementsOf(v21);
        PLACES.forEach((added, after) -> assertThat(v1.indexOf(added)).as(added).isEqualTo(v1.indexOf(after) + 1));
    }

    @Test
    void theRulesDictionaryAddsTheTwoConclusionsTheDecisionRulesRead() {
        List<String> v1 = keys(SecurityDecisionPromptDictionary.V1_ENTRIES);
        List<String> rules = keys(SecurityDecisionPromptDictionary.V1_RULES_ENTRIES);

        assertThat(rules).hasSize(v1.size() + 2);
        assertThat(rules.indexOf("DECISION_FACTS.PolicySatisfied")).isEqualTo(rules.indexOf("DECISION_FACTS.Policy") + 1);
        assertThat(rules.indexOf("DECISION_FACTS.DeviationsExplained"))
                .isEqualTo(rules.indexOf("DECISION_FACTS.DeviationsFromBaseline") + 1);
        assertThat(v1).doesNotContain("DECISION_FACTS.PolicySatisfied", "DECISION_FACTS.DeviationsExplained");
        assertThat(SecurityDecisionPromptDictionary.contentDigestV1())
                .isNotEqualTo(SecurityDecisionPromptDictionary.contentDigestV1Rules())
                .isNotEqualTo(SecurityDecisionPromptDictionary.contentDigestV21());
    }

    @Test
    void theRecordsLookedUpLineTellsARecordNotLookedUpFromOneLookedUpAndNotFound() {
        CanonicalSecurityContext.FrictionProfile friction = new CanonicalSecurityContext.FrictionProfile();
        friction.setCheckedRecordKinds(List.of("TICKET"));

        String line = V1LineValues.recordsLookedUp(friction);

        assertThat(line).isEqualTo("approvals not looked up; tickets looked up, none found; assignment not looked up;"
                + " on-call not looked up; travel not looked up; access history not looked up");
        assertFits("DECISION_FACTS", "RecordsLookedUp", line);
        assertThat(V1LineValues.recordsLookedUp(null)).isNull();
    }

    @Test
    void theAddedDecisionFactsStateTheHostsFieldsInTheirForms() {
        CanonicalSecurityContext.RoleScopeProfile scope = new CanonicalSecurityContext.RoleScopeProfile();
        scope.setForbiddenResourceFamilies(List.of("PAYROLL", "BILLING"));
        scope.setForbiddenActionFamilies(List.of("EXPORT"));
        scope.setCurrentResourceFamily("CUSTOMER");
        scope.setCurrentActionFamily("export");
        scope.setActionFamilyDrift(true);
        scope.setNormalApprovalPatterns(List.of("manager sign-off"));

        String denied = V1LineValues.scopeDenied(scope);
        assertThat(denied).isEqualTo("denied categories PAYROLL, BILLING; category CUSTOMER in denied: no;"
                + " denied actions EXPORT; action export in denied: yes; host drift: category not stated, action yes");
        assertFits("DECISION_FACTS", "ScopeDenied", denied);
        assertFits("DECISION_FACTS", "ScopeHabits", V1LineValues.scopeHabits(scope));

        CanonicalSecurityContext.Delegation delegation = CanonicalSecurityContext.Delegation.builder()
                .approvalRequired(true).privilegedExportAllowed(false).build();
        String controls = V1LineValues.delegationControls(delegation);
        assertThat(controls).isEqualTo("approval required: yes; privileged export allowed: no");
        assertFits("DECISION_FACTS", "DelegationControls", controls);

        CanonicalSecurityContext tenants = new CanonicalSecurityContext();
        tenants.setActor(CanonicalSecurityContext.Actor.builder().tenantId("acme").build());
        tenants.getAttributes().put("tenantId", "beta");
        String tenantMatch = V1LineValues.tenantMatch(tenants);
        assertThat(tenantMatch).isEqualTo("actor tenant acme, request tenant beta: differ");
        assertFits("DECISION_FACTS", "TenantMatch", tenantMatch);
    }

    @Test
    void aVerifiedSignalIsOnlyTheOneTheServerIssued() {
        CanonicalSecurityContext.Intent server = CanonicalSecurityContext.Intent.builder()
                .anomalySignal("credential stuffing confirmed")
                .anomalySignalSource(V1LineValues.TRUSTED_SIGNAL_SOURCE).build();
        CanonicalSecurityContext.Intent requester = CanonicalSecurityContext.Intent.builder()
                .anomalySignal("credential stuffing confirmed").anomalySignalSource("UNTRUSTED_REQUEST_HEADER").build();

        String verified = V1LineValues.verifiedSignal(server);

        assertThat(verified).isEqualTo("credential stuffing confirmed (server-issued verification input "
                + V1LineValues.TRUSTED_SIGNAL_SOURCE + ")");
        assertFits("DECISION_FACTS", "VerifiedSignal", verified);
        assertThat(V1LineValues.verifiedSignal(requester)).isNull();
    }

    @Test
    void theAddedSessionRequestAndPastRecordLinesFitTheirForms() {
        CanonicalSecurityContext.SessionNarrativeProfile narrative = new CanonicalSecurityContext.SessionNarrativeProfile();
        narrative.setBurstPattern(true);
        assertFits("SESSION", "BurstPattern", V1LineValues.burstPattern(narrative));

        CanonicalSecurityContext.Session session = new CanonicalSecurityContext.Session();
        session.setRecentChallengeCount(2);
        session.setRecentBlockCount(0);
        String counts = V1LineValues.hostDecisionCounts(session, null);
        assertThat(counts).isEqualTo("host counts: challenges 2, blocks 0, escalations not stated");
        assertFits("SESSION", "HostDecisionCounts", counts);
        assertThat(V1LineValues.hostDecisionCounts(null, null)).isNull();

        CanonicalSecurityContext.Resource resource = new CanonicalSecurityContext.Resource();
        resource.setResourceType("CUSTOMER_RECORD");
        assertFits("REQUEST", "TargetType", V1LineValues.targetType(resource));

        CanonicalSecurityContext.Location location = new CanonicalSecurityContext.Location();
        location.setNetworkZone("CORPORATE");
        assertFits("REQUEST", "NetworkZone", V1LineValues.networkZone(location));
    }

    @Test
    void theV1SystemTextIsTheV21JudgmentWithTheReadingAndHonestySentences() {
        InspectionGolden.Render render = render(MeasuredVariant.RECORD_EXACT, context -> {
        });
        String system = render.systemPrompt();

        String reading = partText("more-reading").lines().findFirst().orElseThrow();
        String honesty = partText("honesty-more").lines().findFirst().orElseThrow();
        assertThat(system).contains(reading, honesty).doesNotContain("Decision rules");
        assertThat(system.indexOf(reading)).isGreaterThan(system.indexOf("How to read the evidence:"))
                .isLessThan(system.indexOf("How to judge:"));
        assertThat(system.indexOf(honesty)).isGreaterThan(system.indexOf("Honesty:"));
        assertThat(system).contains("\n\nHow to judge:\n");
        assertThat(render.executionMetadata().get(PromptExecutionMetadata.USER_PROMPT_LAYOUT_VERSION))
                .isEqualTo(SecurityDecisionPromptSections.USER_PROMPT_LAYOUT_V1);
        assertThat(render.userPrompt()).doesNotContain("PolicySatisfied: ", "DeviationsExplained: ");
    }

    @Test
    void theDecisionRulesComeOnlyWithAVersionThatIncludesThemAndLeaveTheAutomationLineOutForAnAgent() {
        String automation = PreparedPartsEquivalenceTest.MEASURED.path("v20AutomationBoundary").asText().strip();
        String category = PreparedPartsEquivalenceTest.MEASURED.path("v20AutomationCategory").asText().strip();
        String person = render(MeasuredVariant.FALLBACK_EXACT, context -> {
        }).systemPrompt();
        String agent = render(MeasuredVariant.FALLBACK_EXACT, context -> {
            context.getAttributes().put("executionSubjectKind", "AUTONOMOUS_AGENT");
            context.getAttributes().put("agentId", "report-agent");
            context.setDelegation(CanonicalSecurityContext.Delegation.builder().delegated(false)
                    .agentId("report-agent").build());
        }).systemPrompt();

        assertThat(person).contains("Decision rules", "Verified signal boundary", automation);
        assertThat(person.indexOf("Decision rules")).isGreaterThan(person.indexOf("Responses and what they do:"))
                .isLessThan(person.indexOf("Honesty:"));
        assertThat(agent).contains("Decision rules").doesNotContain(automation).doesNotContain(category);
        assertThat(render(MeasuredVariant.RECORD_EXACT, context -> {
        }).systemPrompt()).doesNotContain("Decision rules");
    }

    /**
     * Plan 2.3 B1 (2.8, D2, D10, K32): the minimum action floors are stated when the host enforces them, by any version
     * (MinimumActionRulesSystemTextTest, PreparedPartsEquivalenceTest), never with the v3 rule codes the answer does not
     * cite; a version the host only observes states no floor, the decision rules included or not.
     */
    @Test
    void noVersionStatesTheMinimumActionFloorsWhenTheHostOnlyObservesThem() {
        String rules = render(MeasuredVariant.FALLBACK_SIMILAR, context -> {
        }).systemPrompt();
        String product = render(MeasuredVariant.RECORD_SIMILAR, context -> {
        }).systemPrompt();

        assertThat(rules).contains("Decision rules").doesNotContain("Minimum action rules").doesNotContain("MIN_P");
        assertThat(product).doesNotContain("Minimum action rules").doesNotContain("Decision rules");
    }

    /** The text of a part of the product prompt document (plan 6-1: the sentences are the document's). */
    static String partText(String key) {
        return SecurityDecisionPromptDocument.product().systemPart(key).orElseThrow().text();
    }

    private static List<String> keys(List<PromptDictionaryEntry> entries) {
        List<String> keys = new ArrayList<>();
        entries.forEach(entry -> keys.add(entry.block().name() + "." + entry.name()));
        return keys;
    }

    private static void assertFits(String block, String name, String value) {
        PromptDictionaryEntry entry = SecurityDecisionPromptDictionary.V1_RULES_ENTRIES.stream()
                .filter(candidate -> candidate.block() == PromptBlock.valueOf(block) && candidate.name().equals(name))
                .findFirst().orElseThrow();
        assertThat(value).as(block + "." + name).isNotNull();
        assertThat(Pattern.matches(entry.formatPattern(), value)).as(block + "." + name + " = " + value).isTrue();
    }

    /** The L1 render of the first golden case by the variant's version, after a change to its sealed context. */
    static InspectionGolden.Render render(MeasuredVariant variant, Consumer<CanonicalSecurityContext> change) {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        JsonNode goldenCase = golden.cases().get(0);
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
        SecurityDecisionGoldenRender.RenderedCase rendered = golden.renderVersion(changed,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, new TieredStrategyProperties(), variant.store(),
                MeasuredVariant.VERSION, Map.of());
        return new InspectionGolden.Render(rendered.caseKey(), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT,
                rendered.systemText(), rendered.userText(), rendered.canonicalContext(),
                rendered.executionMetadata().toMetadataMap(), goldenCase.path("ragResults").toString(),
                goldenCase.path("requestFacts").toString());
    }
}
