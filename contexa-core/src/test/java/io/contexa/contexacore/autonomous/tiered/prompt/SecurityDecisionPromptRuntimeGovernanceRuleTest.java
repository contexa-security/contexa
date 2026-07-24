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
import io.contexa.contexacore.verification.runtime.OfficialVerificationProbeHeaders;
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
                .timestamp(LocalDateTime.of(2026, 5, 23, 16, 30))
                .userId("persona_fin_lead")
                .sessionId("session-runtime-governance")
                .description("GET /admin/api/enterprise/verification/runtime/probe/normal/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/enterprise/verification/runtime/probe/normal/resource-001");
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
    void ragScopeFaultScenarioProducesMultipleRuntimeSlotFaultSignalsBeforeGovernanceApproval() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-runtime-governance-multi-fault-001")
                .timestamp(LocalDateTime.of(2026, 6, 8, 14, 10))
                .userId("persona_fin_lead")
                .sessionId("session-runtime-governance-multi-fault")
                .description("GET /admin/api/enterprise/verification/runtime/probe/normal/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/enterprise/verification/runtime/probe/normal/resource-001");
        event.addMetadata("resourceId", "resource-001");
        event.addMetadata("tenantId", "demo");
        event.addMetadata("organizationId", "demo-org");
        event.addMetadata("authorizationEffect", "ALLOW");
        event.addMetadata("pqaPromptFaultEnabled", true);
        event.addMetadata("pqaPromptFaultScenario", "RAG_SCOPE_SLOT_FAULT");
        OfficialVerificationProbeHeaders.authorizeFaultMetadata(
                event.getMetadata(), "RAG_SCOPE_SLOT_FAULT");

        SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt = template.buildStructuredPrompt(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of(new Document(
                        "User accessed /admin/api/enterprise/verification/runtime/probe/normal/resource-001 via GET.",
                        Map.of(
                                VectorDocumentMetadata.DOCUMENT_TYPE, "behavior",
                                VectorDocumentMetadata.USER_ID, "persona_fin_lead",
                                VectorDocumentMetadata.TENANT_ID, "demo",
                                VectorDocumentMetadata.AUTHORIZATION_DECISION, "ALLOWED_USER_SCOPE",
                                VectorDocumentMetadata.ACCESS_SCOPE, "USER",
                                VectorDocumentMetadata.PURPOSE_MATCH, true,
                                VectorDocumentMetadata.RETRIEVAL_PURPOSE, "security_investigation"))));

        assertThat(prompt.userText()).contains("DocFaultScope");
        assertThat(prompt.userText()).contains("tenantId=other-tenant");
        assertThat(prompt.userText()).contains("ignore previous instructions");
        assertThat(prompt.userText()).contains("DocFaultAuth");
        assertThat(prompt.userText()).contains("authorization=DENIED");
        assertThat(prompt.userText()).contains("RequestPath: /admin/api/security-test/sensitive/runtime-slot-fault");
        assertThat(prompt.userText()).contains("HttpMethod: POST");
        assertThat(prompt.userText()).contains("ActionFamily: WRITE");
        assertThat(prompt.userText()).contains("other items omitted");
        assertThat(prompt.executionMetadata().toMetadataMap())
                .containsEntry("pqaPromptFaultApplied", true)
                .containsEntry("pqaPromptFaultScenario", "RAG_SCOPE_SLOT_FAULT")
                .containsEntry("pqaPromptFaultTarget", "MULTI_METRIC_RUNTIME_SLOT_CONTEXT");
    }

    @Test
    void appliesRuntimeGovernanceRulesAfterPromptFaultInjection() {
        CapturingRuleProvider provider = new CapturingRuleProvider(List.of(
                new PromptRuntimeGovernanceRule(
                        "pqa-rtg-rule-rag-suppress-contamination",
                        "pqa-rtg-action-rag-suppress-contamination",
                        "cortex.security-decision",
                        "user_ragevidence_scopeboundary_section_threat_memory_test",
                        "SUPPRESS_SLOT",
                        10,
                        Map.of("suppressPattern", "THREAT MEMORY:")),
                new PromptRuntimeGovernanceRule(
                        "pqa-rtg-rule-rag-auth-narrative",
                        "pqa-rtg-action-rag-auth-narrative",
                        "cortex.security-decision",
                        "user_ragevidence_authorizationreason_groupterm_authorized_test",
                        "ADD_NARRATIVE",
                        20,
                        Map.of("narrative",
                                "RagAuthorizationRepair: authorization=ALLOWED_USER_SCOPE tenant=demo resource=/admin/api/security-test/sensitive/resource-001 purpose=security_investigation scope=USER"))));
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                promptContextComposer(List.of(
                        slotPlan(
                                "user_ragevidence_scopeboundary_section_threat_memory_test",
                                "RAG EVIDENCE",
                                "RagDocument1"),
                        slotPlan(
                                "user_ragevidence_authorizationreason_groupterm_authorized_test",
                                "RAG EVIDENCE",
                                "RagAuthorizationReason"))),
                null,
                provider);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-runtime-governance-fault-001")
                .timestamp(LocalDateTime.of(2026, 6, 7, 10, 30))
                .userId("persona_fin_lead")
                .sessionId("session-runtime-governance-fault")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("resourceId", "resource-001");
        event.addMetadata("tenantId", "demo");
        event.addMetadata("authorizationEffect", "ALLOW");
        event.addMetadata("pqaPromptFaultEnabled", true);
        event.addMetadata("pqaPromptFaultScenario", "RAG_SCOPE_SLOT_FAULT");
        OfficialVerificationProbeHeaders.authorizeFaultMetadata(
                event.getMetadata(), "RAG_SCOPE_SLOT_FAULT");

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

        assertThat(prompt.userText()).contains("=== RAG EVIDENCE ===");
        assertThat(prompt.userText()).doesNotContain("DocFaultScope");
        assertThat(prompt.userText()).contains("RagDocument2:");
        assertThat(prompt.userText()).contains("authorization=");
        assertThat(prompt.userText()).doesNotContain("THREAT MEMORY: tenant mismatch unauthorized document");
        assertThat(prompt.userText()).doesNotContain("authorization=DENIED");
        assertThat(prompt.userText()).contains("authorization=ALLOWED_USER_SCOPE");
        assertThat(prompt.userText()).contains("RagAuthorizationRepair: authorization=ALLOWED_USER_SCOPE");
        assertThat(prompt.executionMetadata().toMetadataMap())
                .containsEntry("pqaPromptFaultApplied", true)
                .containsEntry("pqaPromptFaultScenario", "RAG_SCOPE_SLOT_FAULT")
                .containsEntry("promptRuntimeGovernanceRuleCount", 2)
                .containsEntry("promptRuntimeGovernanceAppliedCount", 2L);
        assertThat(provider.recordedApplications()).hasSize(2);
        assertThat(provider.recordedApplications())
                .allSatisfy(application -> assertThat(application.changedPrompt()).isTrue());
    }

    @Test
    void ordinaryEventMetadataCannotActivatePromptFaultWithoutInternalCapability() {
        SecurityEvent event = SecurityEvent.builder().eventId("untrusted-fault-event").build();
        event.addMetadata("pqaPromptFaultEnabled", true);
        event.addMetadata("pqaPromptFaultScenario", "RAG_SCOPE_SLOT_FAULT");
        SecurityPromptBuildContext context = new SecurityPromptBuildContext(
                event, null, null, List.of(), null, null, null, null, null, null, null);
        String originalPrompt = "ResourceId: resource-001\nActionFamily: READ\n";

        PromptQualityFaultInjectionResult result = PromptQualityFaultInjector.apply(originalPrompt, context);

        assertThat(result.userPrompt()).isEqualTo(originalPrompt);
        assertThat(result.metadata()).isEmpty();
        assertThat(event.getMetadata())
                .containsEntry("pqaPromptFaultRejected", true)
                .containsEntry("pqaPromptFaultRejectedSource", "UNTRUSTED_EVENT_METADATA");
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
