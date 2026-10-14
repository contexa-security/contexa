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

import java.time.ZoneId;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.inference.ContextCoverageEvaluator;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRule;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleApplication;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleProvider;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlotPlan;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlotPlanProvider;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlotRenderer;
import io.contexa.contexacore.autonomous.context.registry.InMemoryResourceContextRegistry;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionPromptRuntimeGovernanceRuleTest {

    @Test
    void appliesActiveRuntimeGovernanceRulesDuringPromptBuildAndRecordsApplications() {
        CapturingRuleProvider provider = new CapturingRuleProvider(List.of(new PromptRuntimeGovernanceRule(
                "pqa-rtg-rule-runtime-test",
                "pqa-rtg-action-runtime-test",
                "cortex.security-decision",
                "runtime.test.narrative",
                "ADD_NARRATIVE",
                100,
                Map.of("narrative", "RuntimeGovernanceNarrative: preserve browser transition context."))));
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                promptContextComposer(List.of(slotPlan(
                        "runtime.test.narrative",
                        "CURRENT REQUEST AND EVENT",
                        "EventId"))),
                null,
                provider);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-runtime-governance-001")
                .timestamp(LocalDateTime.of(2026, 5, 23, 16, 30).atZone(ZoneId.systemDefault()).toInstant())
                .userId("persona_fin_lead")
                .sessionId("session-runtime-governance")
                .description("GET /admin/api/enterprise/verification/runtime/probe/normal/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/enterprise/verification/runtime/probe/normal/resource-001");
        event.addMetadata("resourceUrl", "/api/security-test/sensitive/resource-001");
        event.addMetadata("protectableResourceUrl", "/api/security-test/sensitive/{resourceId}");
        event.addMetadata("protectableHttpMethod", "GET");
        event.addMetadata("resourceId", "resource-001");
        event.addMetadata("tenantId", "demo");
        event.addMetadata("authorizationEffect", "ALLOW");

        SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt = template.buildStructuredPrompt(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(prompt.userText()).contains("RuntimeGovernanceNarrative: preserve browser transition context.");
        assertThat(provider.requestedContexts()).hasSize(1);
        assertThat(provider.requestedContexts().get(0).promptKey()).isEqualTo("cortex.security-decision");
        assertThat(provider.requestedContexts().get(0).resourceUrl())
                .isEqualTo("/api/security-test/sensitive/{resourceId}");
        assertThat(provider.requestedContexts().get(0).httpMethod()).isEqualTo("GET");
        assertThat(provider.recordedApplications()).hasSize(1);
        assertThat(provider.recordedApplications().get(0).ruleId()).isEqualTo("pqa-rtg-rule-runtime-test");
        assertThat(provider.recordedApplications().get(0).changedPrompt()).isTrue();
        assertThat(provider.recordedSystemPromptHash()).startsWith("sha256:");
        assertThat(provider.recordedUserPromptHash()).startsWith("sha256:");
        assertThat(prompt.executionMetadata().toMetadataMap())
                .containsEntry("promptRuntimeGovernanceRuleCount", 1)
                .containsEntry("promptRuntimeGovernanceAppliedCount", 1L);
        assertThat(prompt.executionMetadata().toMetadataMap())
                .containsEntry("promptRuntimeGovernanceRuleIds", List.of("pqa-rtg-rule-runtime-test"))
                .containsEntry("promptRuntimeGovernanceApplicationRuleIds", List.of("pqa-rtg-rule-runtime-test"))
                .containsEntry("promptRuntimeGovernanceAppliedRuleIds", List.of("pqa-rtg-rule-runtime-test"));
        assertThat((List<Map<String, Object>>) prompt.executionMetadata().toMetadataMap()
                .get("promptRuntimeGovernanceApplicationStates"))
                .singleElement()
                .satisfies(applicationState -> assertThat(applicationState)
                        .containsEntry("ruleId", "pqa-rtg-rule-runtime-test")
                        .containsEntry("sourceActionId", "pqa-rtg-action-runtime-test")
                        .containsEntry("slotKey", "runtime.test.narrative")
                        .containsEntry("resultState", "APPLIED")
                        .containsEntry("changedPrompt", true));
    }

    @Test
    void appliesNoveltyNarrativeToItsRenderedSectionWhenRagContainsTheSameLabel() {
        String narrative = "Explain whether the current access hour appears in observed hours.";
        CapturingRuleProvider provider = new CapturingRuleProvider(List.of(new PromptRuntimeGovernanceRule(
                "pqa-rtg-rule-novelty-test",
                "pqa-rtg-action-novelty-test",
                "cortex.security-decision",
                "user.novelty.current-access-hour",
                "ADD_NARRATIVE",
                100,
                Map.of("narrative", narrative))));
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                promptContextComposer(List.of(slotPlan(
                        "user.novelty.current-access-hour",
                        "PERSONAL WORK PROFILE",
                        "CurrentAccessHourPresentInObservedHours"))),
                null,
                provider);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-runtime-governance-novelty-001")
                .timestamp(LocalDateTime.of(2026, 7, 24, 11, 30).atZone(ZoneId.systemDefault()).toInstant())
                .userId("persona_hr_admin")
                .sessionId("session-runtime-governance-novelty")
                .description("GET /api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/api/security-test/sensitive/resource-001");
        event.addMetadata("protectableResourceUrl", "/api/security-test/sensitive/{resourceId}");
        event.addMetadata("protectableHttpMethod", "GET");
        event.addMetadata("resourceId", "resource-001");
        event.addMetadata("tenantId", "demo");
        event.addMetadata("authorizationEffect", "ALLOW");

        SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt = template.buildStructuredPrompt(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of(new Document(
                        "CurrentAccessHourPresentInObservedHours: historical document text",
                        Map.of(
                                VectorDocumentMetadata.DOCUMENT_TYPE, "behavior",
                                VectorDocumentMetadata.USER_ID, "persona_hr_admin",
                                VectorDocumentMetadata.TENANT_ID, "demo",
                                VectorDocumentMetadata.AUTHORIZATION_DECISION, "ALLOWED_USER_SCOPE",
                                VectorDocumentMetadata.ACCESS_SCOPE, "USER",
                                VectorDocumentMetadata.PURPOSE_MATCH, true,
                                VectorDocumentMetadata.RETRIEVAL_PURPOSE, "security_investigation"))));

        assertThat(prompt.userText()).contains(narrative);
        assertThat(provider.recordedApplications())
                .singleElement()
                .satisfies(application -> assertThat(application)
                        .extracting(
                                PromptRuntimeGovernanceRuleApplication::resultState,
                                PromptRuntimeGovernanceRuleApplication::changedPrompt)
                        .containsExactly("APPLIED", true));
    }

    /**
     * W3-14: a v20 render offers its rules to the dictionary slots only, so the v19 rules the v19 descriptor still
     * returns (until W3-16) leave the v20 prompt as it is. The renderer injects no fault (R4-C9), so the rules meet the
     * prompt as it was drawn.
     */
    @Test
    void aV20RenderTakesDictionaryRulesAndLeavesV19RulesOut() {
        CapturingRuleProvider provider = new CapturingRuleProvider(List.of(
                new PromptRuntimeGovernanceRule(
                        "pqa-rtg-rule-v19-auth-narrative",
                        "pqa-rtg-action-v19-auth-narrative",
                        "cortex.security-decision",
                        "user_ragevidence_authorizationreason_groupterm_authorized_test",
                        "ADD_NARRATIVE",
                        5,
                        Map.of("narrative", "RagAuthorizationRepair: authorization=ALLOWED_USER_SCOPE")),
                new PromptRuntimeGovernanceRule(
                        "pqa-rtg-rule-v20-rag-scope",
                        "pqa-rtg-action-v20-rag-scope",
                        "cortex.security-decision",
                        "PAST RECORDS.PastRecordsState",
                        "SUPPRESS_SLOT",
                        10,
                        Map.of("checkCode", "rag_scope_boundary")),
                new PromptRuntimeGovernanceRule(
                        "pqa-rtg-rule-v20-rag-auth",
                        "pqa-rtg-action-v20-rag-auth",
                        "cortex.security-decision",
                        "PAST RECORDS.PastRecordsState",
                        "ADD_NARRATIVE",
                        20,
                        Map.of("checkCode", "rag_authorization_reason",
                                "narrative", "Each record must say why it is authorized."))));
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                properties,
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer(),
                null,
                provider);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-runtime-governance-v20-fault-001")
                .timestamp(LocalDateTime.of(2026, 6, 7, 10, 30).atZone(ZoneId.systemDefault()).toInstant())
                .userId("persona_fin_lead")
                .sessionId("session-runtime-governance-v20-fault")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("resourceId", "resource-001");
        event.addMetadata("tenantId", "demo");
        event.addMetadata("authorizationEffect", "ALLOW");

        SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt = template.buildStructuredPrompt(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of(new Document(
                        "User accessed /admin/api/security-test/sensitive/resource-001 via GET.",
                        Map.of(
                                VectorDocumentMetadata.DOCUMENT_TYPE, "behavior",
                                VectorDocumentMetadata.USER_ID, "persona_fin_lead",
                                VectorDocumentMetadata.TENANT_ID, "demo",
                                VectorDocumentMetadata.AUTHORIZATION_DECISION, "ALLOWED_USER_SCOPE",
                                VectorDocumentMetadata.ACCESS_SCOPE, "USER",
                                VectorDocumentMetadata.PURPOSE_MATCH, true,
                                VectorDocumentMetadata.RETRIEVAL_PURPOSE, "security_investigation"))));

        assertThat(prompt.userText())
                .startsWith("=== USER BASELINE")
                .doesNotContain("RAG EVIDENCE")
                .doesNotContain("RagAuthorizationRepair")
                .contains("PastRecordsState: 1 record of 1 candidates (1 authorized, 0 denied, relevance "
                        + "SAME_RESOURCE, PROJECTED)\n");
        assertThat(prompt.executionMetadata().toMetadataMap())
                .doesNotContainKey("pqaPromptFaultApplied")
                .containsEntry("promptRuntimeGovernanceRuleCount", 3);
        assertThat(provider.recordedApplications())
                .extracting(PromptRuntimeGovernanceRuleApplication::resultState)
                // The v19 rule never reaches the prompt; the v20 rules reach their dictionary slot and find nothing to
                // suppress, and a free-text narrative is not an entry line.
                .containsExactly("SKIPPED_SLOT_NOT_IN_DICTIONARY", "SKIPPED_NO_MATCH",
                        "SKIPPED_FREE_TEXT_ON_DICTIONARY_PROMPT");
    }

    /**
     * W3-14: a v19 render leaves out a rule of the v20 dictionary even when the slot contract rows give its slot key a
     * plan (as the enterprise rows of W3-17 will), so a v20 rule never rewrites the v19 line of the same name.
     */
    @Test
    void aV19RenderLeavesDictionaryRulesOutWhateverTheSlotRowsSay() {
        CapturingRuleProvider provider = new CapturingRuleProvider(List.of(
                new PromptRuntimeGovernanceRule(
                        "pqa-rtg-rule-v20-effect",
                        "pqa-rtg-action-v20-effect",
                        "cortex.security-decision",
                        "DECISION FACTS.AuthorizationEffect",
                        "UPDATE_SLOT_VALUE",
                        10,
                        Map.of("label", "AuthorizationEffect",
                                "renderedValue", "ALLOW by policy W314 (METHOD_AUTHORIZATION_CHECK)"))));
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                promptContextComposer(List.of(slotPlan(
                        "DECISION FACTS.AuthorizationEffect", "DECISION FACTS", "AuthorizationEffect"))),
                null,
                provider);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-runtime-governance-v19-dictionary-rule-001")
                .timestamp(LocalDateTime.of(2026, 6, 7, 10, 30).atZone(ZoneId.systemDefault()).toInstant())
                .userId("persona_fin_lead")
                .sessionId("session-runtime-governance-v19-dictionary-rule")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("authorizationEffect", "ALLOW");

        SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt = template.buildStructuredPrompt(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(prompt.userText())
                .doesNotStartWith("=== USER BASELINE")
                .containsPattern("(?m)^AuthorizationEffect: ")
                .doesNotContain("W314");
        assertThat(provider.recordedApplications())
                .extracting(PromptRuntimeGovernanceRuleApplication::resultState)
                .containsExactly("SKIPPED_DICTIONARY_SLOT_ON_SECTION_PROMPT");
    }

    private static PromptContextComposer promptContextComposer(List<PromptSlotPlan> plans) {
        PromptSlotPlanProvider provider = new PromptSlotPlanProvider() {
            @Override
            public PromptSlotPlan planFor(String sectionKey, String labelKey) {
                return PromptSlotPlan.unscoped(sectionKey, labelKey);
            }

            @Override
            public List<PromptSlotPlan> plansForSlotKey(String promptKey, String slotKey) {
                return plans.stream()
                        .filter(plan -> plan.slotKey().equals(slotKey))
                        .toList();
            }
        };
        return new PromptContextComposer(new PromptSlotRenderer(), provider);
    }

    private static PromptSlotPlan slotPlan(String slotKey, String sectionKey, String labelKey) {
        return new PromptSlotPlan(
                slotKey,
                sectionKey,
                labelKey,
                "canonical." + labelKey,
                "PromptContextComposer",
                "P1_HIGH_VALUE",
                "PROTECT");
    }

    private static final class CapturingRuleProvider implements PromptRuntimeGovernanceRuleProvider {

        private final List<PromptRuntimeGovernanceRule> rules;
        private final List<PromptRuntimeGovernanceRuleContext> requestedContexts = new ArrayList<>();
        private final List<PromptRuntimeGovernanceRuleApplication> recordedApplications = new ArrayList<>();
        private String recordedSystemPromptHash;
        private String recordedUserPromptHash;

        private CapturingRuleProvider(List<PromptRuntimeGovernanceRule> rules) {
            this.rules = rules;
        }

        @Override
        public List<PromptRuntimeGovernanceRule> activeRules(PromptRuntimeGovernanceRuleContext context) {
            requestedContexts.add(context);
            return rules;
        }

        @Override
        public void recordApplications(
                PromptRuntimeGovernanceRuleContext context,
                List<PromptRuntimeGovernanceRuleApplication> applications,
                String systemPromptHash,
                String userPromptHash) {
            recordedApplications.addAll(applications);
            recordedSystemPromptHash = systemPromptHash;
            recordedUserPromptHash = userPromptHash;
        }

        private List<PromptRuntimeGovernanceRuleContext> requestedContexts() {
            return requestedContexts;
        }

        private List<PromptRuntimeGovernanceRuleApplication> recordedApplications() {
            return recordedApplications;
        }

        private String recordedSystemPromptHash() {
            return recordedSystemPromptHash;
        }

        private String recordedUserPromptHash() {
            return recordedUserPromptHash;
        }
    }
}
