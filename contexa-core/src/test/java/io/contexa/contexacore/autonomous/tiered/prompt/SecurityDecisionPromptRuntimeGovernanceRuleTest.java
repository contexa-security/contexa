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

    /** An active rule of a dictionary slot is applied while the prompt is built, and its application is recorded. */
    @Test
    void appliesActiveRuntimeGovernanceRulesDuringPromptBuildAndRecordsApplications() {
        CapturingRuleProvider provider = new CapturingRuleProvider(List.of(new PromptRuntimeGovernanceRule(
                "pqa-rtg-rule-runtime-test",
                "pqa-rtg-action-runtime-test",
                "cortex.security-decision",
                "REQUEST.Size",
                "ADD_SLOT",
                100,
                Map.of("renderedValue", "Size: 4,831 items"))));
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer(),
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

        assertThat(prompt.userText()).contains("\nSize: 4,831 items\n");
        assertThat(prompt.userText().indexOf("\nSize: 4,831 items\n"))
                .isGreaterThan(prompt.userText().indexOf("=== REQUEST"))
                .isLessThan(prompt.userText().indexOf("=== RECORDS AND COMPARISONS"));
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
                        .containsEntry("slotKey", "REQUEST.Size")
                        .containsEntry("resultState", "APPLIED")
                        .containsEntry("changedPrompt", true));
    }

    /**
     * W3-14: a render offers its rules to the dictionary slots only, so a rule of a section label that no dictionary
     * slot holds leaves the prompt as it is. The renderer injects no fault (R4-C9), so the rules meet the prompt as it
     * was drawn.
     */
    @Test
    void aRenderTakesDictionaryRulesAndLeavesARuleWithoutADictionarySlotOut() {
        CapturingRuleProvider provider = new CapturingRuleProvider(List.of(
                new PromptRuntimeGovernanceRule(
                        "pqa-rtg-rule-section-auth-narrative",
                        "pqa-rtg-action-section-auth-narrative",
                        "cortex.security-decision",
                        "user_ragevidence_authorizationreason_groupterm_authorized_test",
                        "ADD_NARRATIVE",
                        5,
                        Map.of("narrative", "RagAuthorizationRepair: authorization=ALLOWED_USER_SCOPE")),
                new PromptRuntimeGovernanceRule(
                        "pqa-rtg-rule-dictionary-rag-scope",
                        "pqa-rtg-action-dictionary-rag-scope",
                        "cortex.security-decision",
                        "PAST RECORDS.PastRecordsState",
                        "SUPPRESS_SLOT",
                        10,
                        Map.of("checkCode", "rag_scope_boundary")),
                new PromptRuntimeGovernanceRule(
                        "pqa-rtg-rule-dictionary-rag-auth",
                        "pqa-rtg-action-dictionary-rag-auth",
                        "cortex.security-decision",
                        "PAST RECORDS.PastRecordsState",
                        "ADD_NARRATIVE",
                        20,
                        Map.of("checkCode", "rag_authorization_reason",
                                "narrative", "Each record must say why it is authorized."))));
        TieredStrategyProperties properties = new TieredStrategyProperties();
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
                .eventId("event-runtime-governance-dictionary-fault-001")
                .timestamp(LocalDateTime.of(2026, 6, 7, 10, 30).atZone(ZoneId.systemDefault()).toInstant())
                .userId("persona_fin_lead")
                .sessionId("session-runtime-governance-dictionary-fault")
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
                // The section rule never reaches the prompt; the dictionary rules reach their slot and find nothing to
                // suppress, and a free-text narrative is not an entry line.
                .containsExactly("SKIPPED_SLOT_NOT_IN_DICTIONARY", "SKIPPED_NO_MATCH",
                        "SKIPPED_FREE_TEXT_ON_DICTIONARY_PROMPT");
    }

    /**
     * Plan 2.3 A10: a render moves a rule written for a label of the earlier section prompt to the dictionary slot that
     * label went to, so the rule reaches the line of that fact.
     */
    @Test
    void aRenderMovesARuleOfASectionLabelToTheSlotItsLabelWentTo() {
        PromptRuntimeGovernanceRule rule = new PromptRuntimeGovernanceRule(
                "pqa-rtg-rule-section-request-path",
                "pqa-rtg-action-section-request-path",
                "cortex.security-decision",
                "user_request_requestpath_v1_test",
                "SUPPRESS_SLOT",
                10,
                Map.of("label", "RequestPath", "sectionKey", "CURRENT REQUEST AND EVENT"));
        PromptContextComposer contract = promptContextComposer(List.of(slotPlan(
                "user_request_requestpath_v1_test", "CURRENT REQUEST AND EVENT", "RequestPath")));
        CapturingRuleProvider provider = new CapturingRuleProvider(List.of(rule));

        String text = renderWithRules(contract, provider);

        assertThat(provider.recordedApplications())
                .extracting(PromptRuntimeGovernanceRuleApplication::resultState).containsExactly("APPLIED");
        assertThat(provider.recordedApplications().get(0).slotKey()).isEqualTo("REQUEST.Action");
        assertThat(text).doesNotContainPattern("(?m)^(\\[[A-Z]\\d+\\] )?Action: ");
    }

    private static String renderWithRules(PromptContextComposer contract, CapturingRuleProvider provider) {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                contract,
                null,
                provider);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-runtime-governance-moved-rule")
                .timestamp(LocalDateTime.of(2026, 6, 7, 10, 30).atZone(ZoneId.systemDefault()).toInstant())
                .userId("persona_fin_lead")
                .sessionId("session-runtime-governance-moved-rule")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("authorizationEffect", "ALLOW");
        return template.buildStructuredPrompt(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of()).userText();
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
