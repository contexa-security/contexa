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

import io.contexa.contexacore.autonomous.context.inference.ContextCoverageEvaluator;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.registry.InMemoryResourceContextRegistry;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptEvidenceCompleteness;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionStandardPromptTemplateTest {

    @Test
    void canonicalContextCacheSeparatesRevisionsAndReturnsDefensiveSnapshots() {
        AtomicInteger resolutions = new AtomicInteger();
        CanonicalSecurityContextProvider provider = event -> {
            resolutions.incrementAndGet();
            return Optional.of(CanonicalSecurityContext.builder()
                    .actor(CanonicalSecurityContext.Actor.builder()
                            .userId(String.valueOf(event.getMetadata().get("canonicalUser")))
                            .build())
                    .build());
        };
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                provider,
                new PromptContextComposer(),
                template.getPromptGovernanceDescriptor());
        SecurityEvent event = SecurityEvent.builder().eventId("shared-event-id").build();
        event.addMetadata("evidenceRevision", 1);
        event.addMetadata("canonicalUser", "revision-one");

        CanonicalSecurityContext first = sections.resolveCanonicalSecurityContext(event).orElseThrow();
        first.getActor().setUserId("caller-mutation");
        CanonicalSecurityContext cachedCopy = sections.resolveCanonicalSecurityContext(event).orElseThrow();
        event.addMetadata("evidenceRevision", 2);
        event.addMetadata("canonicalUser", "revision-two");
        CanonicalSecurityContext revised = sections.resolveCanonicalSecurityContext(event).orElseThrow();

        assertThat(cachedCopy.getActor().getUserId()).isEqualTo("revision-one");
        assertThat(revised.getActor().getUserId()).isEqualTo("revision-two");
        assertThat(resolutions).hasValue(2);
    }

    @Test
    void omittedOptionalSectionsDoNotMakeAnOtherwiseUsablePromptIncomplete() {
        CanonicalSecurityContext completeRequiredContext = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder().userId("alice").build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-optional")
                        .mfaVerified(true)
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("resource-optional")
                        .requestPath("/resource-optional")
                        .httpMethod("GET")
                        .sensitivity("NORMAL")
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("USER"))
                        .scopeTags(List.of("READ"))
                        .authorizationEffect("ALLOW")
                        .build())
                .build();
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(), new TieredStrategyProperties());
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                event -> Optional.of(completeRequiredContext),
                new PromptContextComposer(),
                template.getPromptGovernanceDescriptor());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-optional-sections")
                .userId("alice")
                .sessionId("session-optional")
                .build();
        SecurityDecisionStandardPromptTemplate.SessionContext session =
                new SecurityDecisionStandardPromptTemplate.SessionContext();
        session.setUserId("alice");
        session.setSessionId("session-optional");

        var prompt = sections.buildStructuredPrompt(event, session, null, List.of());

        assertThat(prompt.executionMetadata().promptEvidenceCompleteness())
                .isNotEqualTo(PromptEvidenceCompleteness.INCOMPLETE);
    }

    @Test
    @DisplayName("governed standard prompt should keep core contract sections only")
    void generatePromptShouldUseGovernedStandardTemplate() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-001")
                .timestamp(LocalDateTime.of(2026, 3, 24, 10, 30))
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("203.0.113.10")
                .description("POST /api/customer/export")
                .build();
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("requestPath", "/api/customer/export");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");
        sessionContext.setRequestCount(5);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())
        );

        String systemPrompt = template.generateSystemPrompt(request, "");
        String userPrompt = template.generateUserPrompt(request, "");
        PromptGovernanceDescriptor descriptor = template.getPromptGovernanceDescriptor();
        PromptExecutionMetadata executionMetadata = template.buildStructuredPrompt(
                event,
                sessionContext,
                behaviorAnalysis,
                List.of()
        ).executionMetadata();

        assertThat(systemPrompt).contains("You are a Zero Trust security analyst AI for CONTEXA.");
        assertThat(systemPrompt).contains("Decide whether the current application action should be trusted now.");
        assertThat(systemPrompt).contains("<output_format>");
        assertThat(systemPrompt).contains("Return only one minified JSON object.");
        assertThat(systemPrompt).doesNotContain("Required key order:");
        assertThat(systemPrompt).contains("action is the only required key.");
        assertThat(systemPrompt).contains("\"required\":[\"action\"]");
        assertThat(systemPrompt).doesNotContain("\"required\":[\"action\",\"confidence\"");
        assertThat(systemPrompt).contains("When present, riskScore and confidence must be JSON numbers between 0.0 and 1.0.");
        assertThat(systemPrompt).contains("When present, reasoning must be one concise evidence-based sentence.");
        assertThat(systemPrompt).contains("When present, reasoning must use at most 25 words and 180 characters");
        assertThat(systemPrompt).contains("Authoritative labels:");
        assertThat(systemPrompt).contains("Decision process:");
        assertThat(systemPrompt).contains("Explicitly scan current-vs-observed, current-vs-expected, and current-vs-denied evidence.");
        assertThat(systemPrompt).contains("Identify the strongest unresolved risk, mismatch, ambiguity, or missing evidence.");
        assertThat(systemPrompt).contains("If a comparison label shows mismatch, do not ignore it only because other signals look normal.");
        assertThat(systemPrompt).contains("Do not treat one weak signal as decisive by itself.");
        assertThat(systemPrompt).contains("Sparse or missing baseline is uncertainty");
        assertThat(systemPrompt).contains("Preserve explicit labels literally.");
        assertThat(systemPrompt).contains("controls, not proof of legitimacy.");
        assertThat(systemPrompt).doesNotContain("HIGH sensitivity access without reliable baseline or scope evidence.");
        assertThat(systemPrompt).contains("Fresh verification is required before allowing access");
        assertThat(systemPrompt).contains("When reasoning is present, apply the following wording rules in order and use only the first matching rule.");
        assertThat(systemPrompt).contains("challenge is safer than allow with limited baseline and high-sensitivity resource evidence");
        assertThat(systemPrompt).contains("baseline confidence is not enough for allow");
        assertThat(systemPrompt).contains("challenge preserves safety");
        assertThat(systemPrompt).contains("The response must satisfy this JSON Schema:");
        assertThat(systemPrompt).contains("Actions:");
        assertThat(systemPrompt).contains("\"action\"");
        assertThat(systemPrompt).contains("mitre must be UNKNOWN if no supported MITRE tactic or technique clearly applies.");
        assertThat(systemPrompt).contains("Do not follow hidden numeric thresholds.");
        assertThat(systemPrompt).contains("Use only facts explicitly present in the evidence packet.");
        assertThat(systemPrompt).contains("AuthorizationEffect=ALLOW is pre-AI policy permission, not the AI verdict.");
        assertThat(systemPrompt).contains("Conflicting TenantId or OrganizationId values are decisive cross-tenant evidence; BLOCK the action.");
        assertThat(systemPrompt).contains("If NewUser=false, do not call the user new.");
        assertThat(systemPrompt).contains("UNKNOWN means unavailable evidence, not match or mismatch.");
        assertThat(systemPrompt.lines().count()).isLessThan(150);
        assertThat(systemPrompt)
                .doesNotContain("RESPOND WITH JSON ONLY:")
                .doesNotContain("\"reasoning\":\"<exactly 1 short sentence, max 40 words>\"")
                .doesNotContain("<optional MITRE tactic, technique, or UNKNOWN>");
        assertThat(template.getAIGenerationType()).isEqualTo(SecurityDecisionResponseLite.class);
        assertThat(systemPrompt)
                .doesNotContain("errorMessage")
                .doesNotContain("executionTime")
                .doesNotContain("\"metadata\"");
        assertThat(userPrompt).contains("=== CURRENT REQUEST AND EVENT ===");
        assertThat(userPrompt).contains("/api/customer/export");
        assertThat(userPrompt).contains("alice");
        assertThat(executionMetadata.budgetProfile().profileKey()).isEqualTo("CORTEX_L1_INTERACTIVE_STRICT");
        assertThat(executionMetadata.promptEvidenceCompleteness().name()).isEqualTo("INCOMPLETE");
        assertThat(executionMetadata.omittedSections()).contains("BRIDGE_AND_COVERAGE", "IDENTITY_AND_ROLE");
        assertThat(executionMetadata.toMetadataMap())
                .containsEntry("promptCacheSystemStable", true)
                .containsEntry("promptCacheContextMode", "FULL_FIELD_PRESERVED")
                .containsEntry("pqaReferencePrompt", "FINAL_USER_PROMPT")
                .containsEntry("pqaRawPromptRole", "TRACEABILITY_ONLY")
                .containsEntry("pqaPromptCachePolicy", "SYSTEM_STATIC_CONTEXT_FIELD_PRESERVED_V1");
        assertThat(executionMetadata.toMetadataMap().get("promptCacheSystemHash"))
                .asString()
                .startsWith("sha256:");
        assertThat(descriptor.promptVersion()).isEqualTo("2026.07.26-v5");
        assertThat(descriptor.contractVersion()).isEqualTo("CORTEX_PROMPT_CONTRACT_V2");
        assertThat(descriptor.releaseStatus().name()).isEqualTo("PRODUCTION");
        assertThat(descriptor.releaseApprovalReference()).isEqualTo("B5-02-D03-TENANT-ISOLATION-2026-07-26-V5");
        assertThat(descriptor.evaluationBaselineReference()).isEqualTo("2026.07.26-b5-v5-gpt-5-nano-tenant-isolation");
        assertThat(descriptor.rollbackPromptVersion()).isEqualTo("2026.07.24-v4");
        assertThat(descriptor.supportedModelProfiles()).contains("STRICT_JSON_SCHEMA");
    }

    @Test
    @DisplayName("system prompt should remain stable while user prompt carries request-specific evidence")
    void generatePromptShouldKeepSystemPromptStableAcrossDifferentRequests() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityDecisionRequest firstRequest = requestFor("alice", "/api/customer/export", "POST");
        SecurityDecisionRequest secondRequest = requestFor("bob", "/admin/api/security-test/normal/resource-001", "GET");

        String firstSystemPrompt = template.generateSystemPrompt(firstRequest, "");
        String secondSystemPrompt = template.generateSystemPrompt(secondRequest, "");
        String firstUserPrompt = template.generateUserPrompt(firstRequest, "");
        String secondUserPrompt = template.generateUserPrompt(secondRequest, "");

        assertThat(firstSystemPrompt).isEqualTo(secondSystemPrompt);
        assertThat(firstUserPrompt).isNotEqualTo(secondUserPrompt);
        assertThat(firstSystemPrompt)
                .doesNotContain("alice")
                .doesNotContain("bob")
                .doesNotContain("/api/customer/export")
                .doesNotContain("/admin/api/security-test/normal/resource-001");
        assertThat(firstUserPrompt).contains("alice").contains("/api/customer/export");
        assertThat(secondUserPrompt).contains("bob").contains("/admin/api/security-test/normal/resource-001");
    }

    @Test
    @DisplayName("runtime rendering should cache only stable system prompt sections")
    void buildStructuredPromptShouldCacheStableSystemSectionsOnly() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());
        SecurityDecisionRequest firstRequest = requestFor("alice", "/api/customer/export", "POST");
        SecurityDecisionRequest secondRequest = requestFor("bob", "/admin/api/security-test/normal/resource-001", "GET");

        SecurityDecisionStandardPromptTemplate.StructuredPrompt firstPrompt = template.buildStructuredPrompt(
                firstRequest.getContext().getSecurityEvent(),
                firstRequest.getContext().getSessionContext(),
                firstRequest.getContext().getBehaviorAnalysis(),
                firstRequest.getContext().getRelatedDocuments());
        SecurityDecisionStandardPromptTemplate.StructuredPrompt secondPrompt = template.buildStructuredPrompt(
                secondRequest.getContext().getSecurityEvent(),
                secondRequest.getContext().getSessionContext(),
                secondRequest.getContext().getBehaviorAnalysis(),
                secondRequest.getContext().getRelatedDocuments());
        Map<String, Object> firstMetadata = firstPrompt.executionMetadata().toMetadataMap();
        Map<String, Object> secondMetadata = secondPrompt.executionMetadata().toMetadataMap();

        assertThat(firstMetadata)
                .containsEntry("promptCacheSystemStable", true)
                .containsEntry("promptCacheSystemHit", false);
        assertThat(secondMetadata)
                .containsEntry("promptCacheSystemStable", true)
                .containsEntry("promptCacheSystemHit", true);
        assertThat(secondMetadata.get("promptCacheSystemHash")).isEqualTo(firstMetadata.get("promptCacheSystemHash"));
        assertThat(secondMetadata.get("promptCacheSystemKey"))
                .asString()
                .doesNotContain("alice")
                .doesNotContain("bob")
                .doesNotContain("/api/customer/export")
                .doesNotContain("/admin/api/security-test/normal/resource-001");
        assertThat(((Number) secondMetadata.get("promptRuntimeSlotCount")).intValue()).isGreaterThan(0);
        assertThat(((Number) secondMetadata.get("promptRuntimeRenderTimeMs")).longValue()).isGreaterThanOrEqualTo(0L);
        assertThat(firstPrompt.userText()).contains("alice").contains("/api/customer/export");
        assertThat(secondPrompt.userText()).contains("bob").contains("/admin/api/security-test/normal/resource-001");
    }

    @Test
    @DisplayName("native structured mode should omit legacy output format wrapper from system prompt")
    void generateSystemPromptShouldOmitOutputFormatWrapperForNativeStructuredMode() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-native-structured")
                .timestamp(LocalDateTime.of(2026, 4, 17, 11, 0))
                .userId("alice")
                .sessionId("session-native")
                .description("POST /api/customer/export")
                .build();

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        new SecurityDecisionStandardPromptTemplate.SessionContext(),
                        new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                        List.of()));
        request.withParameter("structuredOutputMode", "NATIVE_STRUCTURED");

        String systemPrompt = template.generateSystemPrompt(request, "dynamic-metadata");

        assertThat(systemPrompt).doesNotContain("<output_format>");
        assertThat(systemPrompt).doesNotContain("</output_format>");
        assertThat(systemPrompt).doesNotContain("<context>");
        assertThat(systemPrompt).contains("Required key:");
        assertThat(systemPrompt).contains("Optional keys:");
        assertThat(systemPrompt).contains("Minimal schema:");
        assertThat(systemPrompt).contains(SecurityDecisionContractSectionBuilder.MINIMAL_RESPONSE_EXAMPLE);
    }


    @Test
    @DisplayName("cold-start sparse baseline prompt should stay factual and preserve uncertainty framing")
    void generateUserPromptShouldKeepColdStartBaselineFactual() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-cold-start")
                .timestamp(LocalDateTime.of(2026, 4, 4, 19, 6))
                .userId("admin")
                .sessionId("session-cold-start")
                .sourceIp("0:0:0:0:0:0:0:1")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("isNewUser", false);

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("admin");
        sessionContext.setSessionId("session-cold-start");
        sessionContext.setRequestCount(1);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());
        behaviorAnalysis.setPersonalBaselineAvailable(false);
        behaviorAnalysis.setPersonalBaselineEstablished(false);

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of()));

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("BaselineGapSupport:");
        assertThat(userPrompt).contains("- Baseline gap status: SPARSE_PERSONAL_HISTORY");
        assertThat(userPrompt).contains("Sparse personal history is uncertainty, not proof of compromise or legitimacy by itself.");
        assertThat(countOccurrences(userPrompt, "=== PERSONAL WORK PROFILE ===")).isEqualTo(1);
        assertThat(userPrompt).doesNotContain("This could be a first-time attacker");
        assertThat(userPrompt).doesNotContain("Never Trust, Always Verify");
        assertThat(userPrompt).doesNotContain("You CANNOT determine if this behavior is normal");
    }
    @Test
    @DisplayName("configured layer1 default budget profile should flow into direct browser-style prompt generation")
    void generatePromptShouldUseConfiguredLayer1DefaultBudgetProfile() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer1().setDefaultBudgetProfile("CORTEX_L1_INTERACTIVE_STRICT");
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                properties);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-budget-profile")
                .timestamp(LocalDateTime.of(2026, 4, 2, 10, 0))
                .userId("alice")
                .sessionId("session-1")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");

        PromptExecutionMetadata executionMetadata = template.buildStructuredPrompt(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of()
        ).executionMetadata();

        assertThat(executionMetadata.budgetProfile().profileKey())
                .isEqualTo(PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT.profileKey());
        assertThat(executionMetadata.toMetadataMap())
                .containsEntry("promptCacheContextMode", "FULL_FIELD_PRESERVED")
                .containsEntry("pqaReferencePrompt", "FINAL_USER_PROMPT");
    }

    @Test
    @DisplayName("current request section should prefer canonical session narrative over behavior fallback")
    void generateUserPromptShouldPreferCanonicalSessionNarrativeOverBehaviorFallback() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-002")
                .timestamp(LocalDateTime.of(2026, 3, 30, 11, 31))
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("203.0.113.10")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("previousPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("previousActionFamily", "READ");
        event.addMetadata("lastRequestIntervalMs", 42000L);
        event.addMetadata("sessionActionSequence", List.of("READ", "READ"));
        event.addMetadata("sessionProtectableSequence", List.of("/admin/api/security-test/sensitive/resource-001", "/admin/api/security-test/sensitive/resource-001"));
        event.addMetadata("bridgeCoverageLevel", "AUTHORIZATION_CONTEXT");
        event.addMetadata("bridgeCoverageSummary", "Bridge resolved authentication and authorization context for the current request.");
        event.addMetadata("bridgeAuthenticationSource", "SECURITY_CONTEXT");
        event.addMetadata("bridgeAuthorizationSource", "HEADER");
        event.addMetadata("bridgeMissingContexts", List.of("AUTHORIZATION_EFFECT"));
        event.addMetadata("authorizationEffectProvenance", "METHOD_INVOCATION_RESULT");
        event.addMetadata("userRoles", List.of("ROLE_ADMIN"));
        event.addMetadata("effectivePermissions", List.of("report.read"));
        event.addMetadata("scopeTags", List.of("customer_data"));
        event.addMetadata("mfaVerified", true);
        event.addMetadata("resourceSensitivity", "HIGH");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");
        sessionContext.setRequestCount(2);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPreviousPath("/admin/api/security-test/evidence/server-truth");
        behaviorAnalysis.setLastRequestIntervalMs(0L);

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())
        );

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("PreviousPath: /admin/api/security-test/sensitive/resource-001");
        assertThat(userPrompt).contains("LastRequestIntervalMs: 42000");
        assertThat(userPrompt).doesNotContain("PreviousPath: /admin/api/security-test/evidence/server-truth");
        assertThat(userPrompt).doesNotContain("LastRequestIntervalMs: 0");
    }

    @Test
    @DisplayName("baseline narrative should stay provisional until personal baseline is established")
    void generateUserPromptShouldKeepBaselineNarrativeProvisionalUntilPersonalBaselineIsEstablished() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-003")
                .timestamp(LocalDateTime.of(2026, 3, 30, 11, 35))
                .userId("alice")
                .sessionId("session-1")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("userRoles", List.of("ADMIN"));

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineEstablished(true);
        behaviorAnalysis.setPersonalBaselineAvailable(true);
        behaviorAnalysis.setPersonalBaselineEstablished(false);
        behaviorAnalysis.setBaselineUpdateCount(1L);
        behaviorAnalysis.setPersonalBaselineEvidence(personalBaselineEvidence(false, 1L));

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())
        );

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("BaselineProfileStatus: PROVISIONAL");
        assertThat(userPrompt).contains("PersonalBaselineStatus: LEARNING_IN_PROGRESS");
        assertThat(userPrompt).contains("BaselineContextSummary:");
        assertThat(userPrompt).doesNotContain("This user normally");
        assertThat(userPrompt).doesNotContain("Frequent paths:");
        assertThat(userPrompt).doesNotContain("BaselineProfileStatus: ESTABLISHED");
    }

    @Test
    @DisplayName("lossless prompt profiles should preserve full prompt fact values without truncation")
    void generateUserPromptShouldPreserveFullFactsForRawIdentityProfile() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        String longBaselineSummary = "personal baseline provisional | resource families="
                + String.join(", ", List.of(
                "PUBLIC", "NORMAL", "SENSITIVE", "CRITICAL", "FINANCE_REPORTS",
                "SECURITY_AUDIT_REPORTS", "TENANT_CONFIGURATION", "PROMPT_GOVERNANCE",
                "OFFICIAL_VERIFICATION_LEDGER", "CERTIFICATE_PROMOTION_QUEUE",
                "REVERIFICATION_EVIDENCE", "RUNTIME_MONITORING_ALERTS"));
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-raw-identity")
                .timestamp(LocalDateTime.of(2026, 5, 11, 16, 52))
                .userId("persona_fin_lead")
                .sessionId("official-verification-session")
                .description("GET /admin/api/enterprise/verification/runtime/probe/normal/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/enterprise/verification/runtime/probe/normal/resource-001");
        event.addMetadata("resourceId", "resource-001");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("persona_fin_lead");
        sessionContext.setSessionId("official-verification-session");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineEstablished(true);
        behaviorAnalysis.setPersonalBaselineAvailable(true);
        behaviorAnalysis.setPersonalBaselineEstablished(false);
        behaviorAnalysis.setBaselineUpdateCount(19L);
        behaviorAnalysis.setPersonalBaselineEvidence(new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL,
                true,
                false,
                19L,
                0.74d,
                List.of("0:0:0:0::/64"),
                List.of("8", "9", "10", "11", "12", "13", "20", "22", "23"),
                List.of("1"),
                List.of("Chrome/120", "Edge/120", "Chrome/148"),
                List.of("Windows", "WINDOWS"),
                List.of("/admin/api/enterprise/verification/*"),
                List.of("PASSWORD", "SSO"),
                List.of("READ"),
                List.of("PUBLIC", "NORMAL", "SENSITIVE", "CRITICAL", "FINANCE_REPORTS",
                        "SECURITY_AUDIT_REPORTS", "TENANT_CONFIGURATION", "PROMPT_GOVERNANCE",
                        "OFFICIAL_VERIFICATION_LEDGER", "CERTIFICATE_PROMOTION_QUEUE",
                        "REVERIFICATION_EVIDENCE", "RUNTIME_MONITORING_ALERTS"),
                longBaselineSummary));

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of()));
        request.withParameter("promptBudgetProfile", PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT.profileKey());

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("BaselineContextSummary: " + longBaselineSummary);
        assertThat(userPrompt).contains("RUNTIME_MONITORING_ALERTS");
        assertThat(userPrompt)
                .doesNotContain("BaselineContextSummary: personal baseline provisional | resource families=PUBLIC, NORMAL, SENSITIVE, CRITICAL, FINANCE_REPORTS, SECURITY_AUDIT_REPORTS, TENANT_CONFIGURATION, PROMPT_GOVERNANCE, OFFICIAL_VERIFICATION_LEDGER, CERTIFICATE_PROMOTION_...");

        SecurityDecisionRequest interactiveRequest = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of()));
        interactiveRequest.withParameter("promptBudgetProfile", PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT.profileKey());

        String interactiveUserPrompt = template.generateUserPrompt(interactiveRequest, "");

        assertThat(interactiveUserPrompt).contains("BaselineContextSummary: " + longBaselineSummary);
        assertThat(interactiveUserPrompt).contains("RUNTIME_MONITORING_ALERTS");
        assertThat(interactiveUserPrompt)
                .doesNotContain("BaselineContextSummary: personal baseline provisional | resource families=PUBLIC, NORMAL, SENSITIVE, CRITICAL, FINANCE_REPORTS, SECURITY_AUDIT_REPORTS, TENANT_CONFIGURATION, PROMPT_GOVERNANCE, OFFICIAL_VERIFICATION_LEDGER, CERTIFICATE_PROMOTION_...");
    }

    @Test
    @DisplayName("sparse personal history should not be promoted into new user")
    void generateUserPromptShouldNotPromoteSparsePersonalHistoryIntoNewUser() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-003b")
                .timestamp(LocalDateTime.of(2026, 4, 1, 15, 0))
                .userId("alice")
                .sessionId("session-2")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("isNewUser", false);
        event.addMetadata("userRoles", List.of("ADMIN"));

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-2");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineAvailable(false);
        behaviorAnalysis.setPersonalBaselineEstablished(false);
        behaviorAnalysis.setOrganizationBaselineAvailable(true);
        behaviorAnalysis.setOrganizationBaselineEstablished(true);
        behaviorAnalysis.setBaselineUpdateCount(1L);
        behaviorAnalysis.setSupportingBaselineEvidence(supportingBaselineEvidence());

        String userPrompt = template.generateUserPrompt(new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())), "");

        assertThat(userPrompt).contains("NewUser: false");
        assertThat(userPrompt).contains("- Baseline gap status: SPARSE_PERSONAL_HISTORY");
        assertThat(userPrompt).contains("- Sparse personal history limits user-specific comparison for this request.");
        assertThat(userPrompt).contains("SupportingBaselineStatus: AVAILABLE_REFERENCE");
        assertThat(userPrompt).contains("SupportingBaselineSummary: organization baseline available");
        assertThat(countOccurrences(userPrompt, "=== PERSONAL WORK PROFILE ===")).isEqualTo(1);
        assertThat(userPrompt).doesNotContain("This is a new user without established behavioral baseline.");
        assertThat(userPrompt).doesNotContain("Personal behavioral baseline is not established yet.");
    }

    @Test
    @DisplayName("typed supporting comparable evidence should render historical scope even without legacy similarEvents")
    void generateUserPromptShouldRenderSupportingComparableEvidenceFromTypedLearningContext() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-supporting-comparables")
                .timestamp(LocalDateTime.of(2026, 4, 18, 16, 0))
                .userId("alice")
                .sessionId("session-supporting")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineAvailable(false);
        behaviorAnalysis.setPersonalBaselineEstablished(false);
        behaviorAnalysis.setOrganizationBaselineAvailable(true);
        behaviorAnalysis.setOrganizationBaselineEstablished(true);
        behaviorAnalysis.setSupportingBaselineEvidence(supportingBaselineEvidence());

        Document supportingDoc = new Document(
                "Reference access from a related cohort user to the same sensitive resource.",
                Map.ofEntries(
                        Map.entry("documentType", "behavior"),
                        Map.entry("userId", "bob@corp"),
                        Map.entry("organizationId", "corp"),
                        Map.entry("requestPath", "/admin/api/security-test/sensitive/resource-001"),
                        Map.entry("hour", 10),
                        Map.entry("dayOfWeek", 1),
                        Map.entry("userAgentBrowser", "Chrome/120"),
                        Map.entry("userAgentOS", "Windows"),
                        Map.entry("authenticationType", "PASSWORD"),
                        Map.entry("actionFamily", "READ"),
                        Map.entry("resourceFamily", "sensitive")));

        String userPrompt = template.generateUserPrompt(new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        new SecurityDecisionStandardPromptTemplate.SessionContext(),
                        behaviorAnalysis,
                        List.of(supportingDoc))), "");

        assertThat(userPrompt).contains("HistoricalComparableEvents:");
        assertThat(userPrompt).contains("HistoricalComparableScope: NO_DIRECT_PERSONAL_COMPARABLE");
        assertThat(userPrompt).contains("HistoricalComparableCount: 0");
        assertThat(userPrompt).contains("HistoricalComparableSummary: Records=0 | NoDirectPersonalComparableEvidence");
        assertThat(userPrompt).contains("=== SUPPORTING LEARNING CONTEXT ===");
        assertThat(userPrompt).contains("SupportingComparableCount: 1");
        assertThat(userPrompt).contains("SupportingComparableExample1:");
    }

    @Test
    @DisplayName("historical comparable evidence should be rendered when RAG documents exist")
    void generateUserPromptShouldRenderHistoricalComparableEventsWhenRagDocumentsExist() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-004")
                .timestamp(LocalDateTime.of(2026, 3, 30, 11, 40))
                .userId("alice")
                .sessionId("session-1")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        behaviorAnalysis,
                        List.of(
                                new Document(
                                        "User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon). Decision: proposedAction=ALLOW",
                                        Map.of(
                                                VectorDocumentMetadata.DOCUMENT_TYPE, "behavior",
                                                VectorDocumentMetadata.USER_ID, "alice",
                                                VectorDocumentMetadata.AUTHORIZATION_DECISION, "ALLOWED_USER_SCOPE",
                                                VectorDocumentMetadata.ACCESS_SCOPE, "USER",
                                                VectorDocumentMetadata.PURPOSE_MATCH, true,
                                                VectorDocumentMetadata.RETRIEVAL_PURPOSE, "security_investigation",
                                                VectorDocumentMetadata.RETRIEVAL_POLICY_SUMMARY, "purpose=security_investigation,user=alice,organization=demo-org,tenant=demo,types=*",
                                                VectorDocumentMetadata.PROVENANCE_SUMMARY, "Security decision memory from runtime event")),
                                new Document(
                                        "Follow-up access revisited /admin/api/security-test/sensitive/resource-001 from the same managed browser.",
                                        Map.of(
                                                VectorDocumentMetadata.DOCUMENT_TYPE, "behavior",
                                                VectorDocumentMetadata.USER_ID, "alice",
                                                VectorDocumentMetadata.AUTHORIZATION_DECISION, "ALLOWED_USER_SCOPE",
                                                VectorDocumentMetadata.ACCESS_SCOPE, "USER",
                                                VectorDocumentMetadata.PURPOSE_MATCH, true,
                                                VectorDocumentMetadata.RETRIEVAL_PURPOSE, "security_investigation",
                                                VectorDocumentMetadata.RETRIEVAL_POLICY_SUMMARY, "purpose=security_investigation,user=alice,organization=demo-org,tenant=demo,types=*",
                                                VectorDocumentMetadata.PROVENANCE_SUMMARY, "Security decision memory from runtime event")))));

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("HistoricalComparableEvents:");
        assertThat(userPrompt).contains("=== RAG EVIDENCE ===");
        assertThat(userPrompt).contains("RagSearchExecuted: true");
        assertThat(userPrompt).contains("RagRetrievalState: AVAILABLE");
        assertThat(userPrompt).contains("RelatedDocumentCount: 2");
        assertThat(userPrompt).contains("RagEvidenceBoundary:");
        assertThat(userPrompt).contains("RagDocument1:");
        assertThat(userPrompt).contains("resourceFamily=SENSITIVE");
        assertThat(userPrompt).contains("pathFamily=/admin/api/security-test/sensitive/*");
        assertThat(userPrompt).contains("authorization=ALLOWED_USER_SCOPE");
        assertThat(userPrompt).contains("retrievalPurpose=security_investigation");
        assertThat(userPrompt).contains("retrievalPolicy=purpose=security_investigation,user=alice,organization=demo-org,tenant=demo,types=*");
        assertThat(userPrompt).contains("HistoricalComparableCount: 2");
        assertThat(userPrompt).contains("HistoricalComparableSummary: Records=2");
        assertThat(userPrompt).contains("ComparableExample1:");
        assertThat(userPrompt).contains("/admin/api/security-test/sensitive/resource-001");
        assertThat(userPrompt).doesNotContain("Decision:");
        assertThat(userPrompt).doesNotContain("proposedAction=");
        assertThat(userPrompt).doesNotContain("ComparableExample2:");
    }

    @Test
    @DisplayName("RAG zero-result state should be visible in final user prompt")
    void generateUserPromptShouldRenderRagZeroResultState() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-rag-zero")
                .timestamp(LocalDateTime.of(2026, 5, 27, 10, 0))
                .userId("persona_fin_lead")
                .sessionId("session-rag-zero")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("ragSearchExecuted", true);
        event.addMetadata("ragRetrievalState", "ZERO_RESULTS");
        event.addMetadata("ragAbsenceReason", "ZERO_RESULTS");
        event.addMetadata("ragProjectionState", "ZERO_RESULTS_DECLARED");
        event.addMetadata("ragCandidateDocumentCount", 0);
        event.addMetadata("ragAuthorizedDocumentCount", 0);
        event.addMetadata("ragDeniedDocumentCount", 0);

        SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt = template.buildStructuredPrompt(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(prompt.userText()).contains("=== RAG EVIDENCE ===");
        assertThat(prompt.userText()).contains("RagSearchExecuted: true");
        assertThat(prompt.userText()).contains("RagRetrievalState: ZERO_RESULTS");
        assertThat(prompt.userText()).contains("RelatedDocumentCount: 0");
        assertThat(prompt.userText()).contains("RagCandidateDocumentCount: 0");
        assertThat(prompt.userText()).contains("RagAuthorizedDocumentCount: 0");
        assertThat(prompt.userText()).contains("RagDeniedDocumentCount: 0");
        assertThat(prompt.userText()).contains("RagPermissionFiltered: false");
        assertThat(prompt.userText()).contains("RagAbsenceReason: ZERO_RESULTS");
        assertThat(prompt.userText()).contains("RagDecisionLimit:");
        assertThat(prompt.executionMetadata().toMetadataMap())
                .containsEntry("ragSearchExecuted", true)
                .containsEntry("ragRetrievalState", "ZERO_RESULTS")
                .containsEntry("ragAbsenceReason", "ZERO_RESULTS")
                .containsEntry("ragStatusProjectedToFinalPrompt", true);
    }

    @Test
    @DisplayName("RAG permission-filtered state should expose candidate and denial counts")
    void generateUserPromptShouldRenderRagPermissionFilteredState() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-rag-filtered")
                .timestamp(LocalDateTime.of(2026, 5, 27, 10, 0))
                .userId("persona_fin_lead")
                .sessionId("session-rag-filtered")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("ragSearchExecuted", true);
        event.addMetadata("ragRetrievalState", "PERMISSION_FILTERED");
        event.addMetadata("ragAbsenceReason", "PERMISSION_FILTERED");
        event.addMetadata("ragProjectionState", "PERMISSION_FILTERED_DECLARED");
        event.addMetadata("ragPermissionFiltered", true);
        event.addMetadata("ragCandidateDocumentCount", 3);
        event.addMetadata("ragAuthorizedDocumentCount", 0);
        event.addMetadata("ragDeniedDocumentCount", 3);

        SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt = template.buildStructuredPrompt(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(prompt.userText()).contains("RagRetrievalState: PERMISSION_FILTERED");
        assertThat(prompt.userText()).contains("RagProjectionState: PERMISSION_FILTERED_DECLARED");
        assertThat(prompt.userText()).contains("RagCandidateDocumentCount: 3");
        assertThat(prompt.userText()).contains("RagAuthorizedDocumentCount: 0");
        assertThat(prompt.userText()).contains("RagDeniedDocumentCount: 3");
        assertThat(prompt.userText()).contains("RagPermissionFiltered: true");
        assertThat(prompt.userText()).contains("RagAbsenceReason: PERMISSION_FILTER_EXCLUDED");
    }

    @Test
    @DisplayName("current request rendering should avoid contradictory duplicate hour and sensitivity narratives")
    void generateUserPromptShouldAvoidContradictoryCurrentHourAndSensitivityNarrative() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-current-request-normalization")
                .timestamp(LocalDateTime.of(2026, 4, 18, 15, 10))
                .userId("alice")
                .sessionId("session-normalized")
                .sourceIp("203.0.113.10")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("currentAccessHour", 15);
        event.addMetadata("mfaVerified", true);
        event.addMetadata("userRoles", List.of("ADMIN"));

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        new SecurityDecisionStandardPromptTemplate.SessionContext(),
                        new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                        List.of()));

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("CurrentAccessHour: 15");
        assertThat(userPrompt).doesNotContain("CurrentHour:");
        assertThat(userPrompt).doesNotContain("This is a SENSITIVE resource.");
    }

    @Test
    @DisplayName("current request rendering should normalize raw authentication vocabulary into semantic labels")
    void generateUserPromptShouldNormalizeAuthenticationVocabulary() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-auth-normalization")
                .timestamp(LocalDateTime.of(2026, 4, 18, 21, 10))
                .userId("alice")
                .sessionId("session-auth-normalized")
                .sourceIp("203.0.113.10")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("authenticationType", "UsernamePasswordAuthenticationToken");
        event.addMetadata("authMethod", "UsernamePasswordAuthenticationToken");
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("mfaVerified", true);
        event.addMetadata("userRoles", List.of("ADMIN"));

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        new SecurityDecisionStandardPromptTemplate.SessionContext(),
                        new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                        List.of()));

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("AuthenticationType: PASSWORD");
        assertThat(userPrompt).doesNotContain("USERNAMEPASSWORDAUTHENTICATIONTOKEN");
    }

    @Test
    @DisplayName("prompt execution metadata should preserve prompt contract audit fields through final metadata build")
    void buildPromptExecutionMetadataShouldPreservePromptContractAuditFields() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-contract-metadata")
                .timestamp(LocalDateTime.of(2026, 4, 18, 21, 10))
                .userId("alice")
                .sessionId("session-contract-metadata")
                .sourceIp("203.0.113.10")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("mfaVerified", true);
        event.addMetadata("userRoles", List.of("ADMIN"));

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        new SecurityDecisionStandardPromptTemplate.SessionContext(),
                        new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                        List.of()));

        String systemPrompt = template.generateSystemPrompt(request, "");
        String userPrompt = template.generateUserPrompt(request, "");
        PromptExecutionMetadata metadata = template.buildPromptExecutionMetadata(request, systemPrompt, userPrompt);

        assertThat(metadata.toMetadataMap())
                .containsKeys(
                        "renderedRequestSnapshot",
                        "renderedLearningSnapshot",
                        "renderedLabelMatrix",
                        "compactedLineCountBySection",
                        "promptContractViolations",
                        "promptContractViolationCount");
    }

    @Test
    @DisplayName("browser follow-up prompt should render bridge and friction evidence")
    void generateUserPromptShouldRenderBridgeAndFrictionEvidenceForBrowserStyleFollowUpRequest() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-005")
                .timestamp(LocalDateTime.of(2026, 3, 30, 11, 45))
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("192.168.1.100")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("previousPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("lastRequestIntervalMs", 42000L);
        event.addMetadata("sessionActionSequence", List.of(
                "11:30 | MFA_COMPLETED (Zero Trust Challenge verified) | 192.168.1.100",
                "11:31 | GET /admin/api/security-test/sensitive/resource-001 | 192.168.1.100"));
        event.addMetadata("bridgeCoverageLevel", "AUTHORIZATION_CONTEXT");
        event.addMetadata("bridgeCoverageSummary", "Bridge completeness reached authentication and authorization context for the current request.");
        event.addMetadata("bridgeAuthenticationSource", "SECURITY_CONTEXT");
        event.addMetadata("bridgeAuthorizationSource", "HEADER");
        event.addMetadata("bridgeMissingContexts", List.of("AUTHORIZATION_EFFECT"));
        event.addMetadata("authorizationEffectProvenance", "METHOD_INVOCATION_RESULT");
        event.addMetadata("effectiveRoles", List.of("ADMIN"));
        event.addMetadata("effectivePermissions", List.of("report.read"));
        event.addMetadata("scopeTags", List.of("customer_data"));
        event.addMetadata("authorizationEffect", "ALLOW");
        event.addMetadata("mfaVerified", true);
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("resourceLabel", "Sensitive Security Test Resource");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");
        sessionContext.setRequestCount(2);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        behaviorAnalysis,
                        List.of(new Document("User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon)"))));

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("=== BRIDGE RESOLUTION CONTEXT ===");
        assertThat(userPrompt).contains("AuthorizationContext:");
        assertThat(userPrompt).contains("AuthorizationEffectProvenance: METHOD_INVOCATION_RESULT");
        assertThat(userPrompt).contains("AuthorizationEffectStageNote: Bridge stamp omitted AuthorizationEffect; final AuthorizationEffect was resolved later from METHOD_INVOCATION_RESULT.");
        assertThat(userPrompt).contains("AuthorizationEffect: ALLOW");
        assertThat(userPrompt).contains("=== FRICTION AND APPROVAL HISTORY ===");
        assertThat(userPrompt).contains("RecentChallengeCount: 1");
        assertThat(userPrompt).contains("HistoricalComparableEvents:");
    }

    @Test
    @DisplayName("evidence should evolve across rounds without regression")
    void generateUserPromptShouldEvolveEvidenceAcrossRoundsWithoutRegression() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-006")
                .timestamp(LocalDateTime.of(2026, 3, 30, 12, 10))
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("192.168.1.100")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("mfaVerified", true);
        event.addMetadata("effectiveRoles", List.of("ADMIN"));
        event.addMetadata("effectivePermissions", List.of("report.read"));
        event.addMetadata("authorizationEffect", "ALLOW");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis round1 = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        round1.setPersonalBaselineEvidence(noDataBaselineEvidence());
        round1.setPersonalBaselineAvailable(false);
        round1.setPersonalBaselineEstablished(false);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis round2 = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        round2.setBaselineEstablished(true);
        round2.setPersonalBaselineAvailable(true);
        round2.setPersonalBaselineEstablished(false);
        round2.setBaselineUpdateCount(1L);
        round2.setPersonalBaselineEvidence(personalBaselineEvidence(false, 1L));

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis round3 = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        round3.setBaselineEstablished(true);
        round3.setPersonalBaselineAvailable(true);
        round3.setPersonalBaselineEstablished(true);
        round3.setBaselineUpdateCount(5L);
        round3.setPersonalBaselineEvidence(personalBaselineEvidence(true, 5L));

        String round1Prompt = template.generateUserPrompt(new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, round1, List.of())), "");
        String round2Prompt = template.generateUserPrompt(new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        round2,
                        List.of(new Document("Round2: previously allowed access for the same sensitive resource")))), "");
        String round3Prompt = template.generateUserPrompt(new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        round3,
                        List.of(
                                new Document("Round2: previously allowed access for the same sensitive resource"),
                                new Document("Round3: repeated follow-up access from the same session and environment")))), "");

        assertThat(round1Prompt).doesNotContain("HistoricalComparableEvents:");
        assertThat(round2Prompt).contains("HistoricalComparableEvents:");
        assertThat(round2Prompt).contains("BaselineProfileStatus: PROVISIONAL");
        assertThat(round2Prompt).contains("BaselineContextSummary:");
        assertThat(round3Prompt).contains("HistoricalComparableEvents:");
        assertThat(round3Prompt).contains("BaselineProfileStatus: ESTABLISHED");
        assertThat(round3Prompt).doesNotContain("BaselineProfileStatus: PROVISIONAL");
        assertThat(countOccurrences(round2Prompt, "Round2:")).isGreaterThanOrEqualTo(1);
        assertThat(countOccurrences(round3Prompt, "Round")).isGreaterThanOrEqualTo(1);
    }

    private SecurityDecisionRequest requestFor(String userId, String path, String method) {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-" + userId)
                .timestamp(LocalDateTime.of(2026, 5, 13, 10, 0))
                .userId(userId)
                .sessionId("session-" + userId)
                .description(method + " " + path)
                .build();
        event.addMetadata("httpMethod", method);
        event.addMetadata("requestPath", path);
        event.addMetadata("resourceSensitivity", "MEDIUM");
        event.addMetadata("mfaVerified", false);

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId(userId);
        sessionContext.setSessionId("session-" + userId);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());

        return new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of()));
    }

    private int countOccurrences(String text, String token) {
        int count = 0;
        int cursor = 0;
        while (cursor >= 0) {
            cursor = text.indexOf(token, cursor);
            if (cursor >= 0) {
                count++;
                cursor += token.length();
            }
        }
        return count;
    }

    private BaselineEvidenceSnapshot personalBaselineEvidence(boolean established, Long observations) {
        return new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL,
                true,
                established,
                observations,
                0.92d,
                List.of("192.168.1"),
                List.of("11"),
                List.of("1"),
                List.of("Chrome/120"),
                List.of("Windows"),
                List.of("/admin/api/*"),
                List.of("PASSWORD"),
                List.of("READ"),
                List.of("sensitive"),
                established
                        ? "personal baseline established | observations=" + observations
                        : "personal baseline provisional | observations=" + observations);
    }

    private BaselineEvidenceSnapshot noDataBaselineEvidence() {
        return new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL,
                false,
                false,
                null,
                null,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                "",
                BaselineEvidenceStatus.NO_DATA,
                "");
    }

    private BaselineEvidenceSnapshot supportingBaselineEvidence() {
        return new BaselineEvidenceSnapshot(
                LearningEvidenceScope.SUPPORTING,
                true,
                true,
                8L,
                0.88d,
                List.of("192.168.1"),
                List.of("9", "10", "11"),
                List.of("1", "2", "3", "4", "5"),
                List.of("Chrome/120"),
                List.of("Windows"),
                List.of("/admin/api/*"),
                List.of("PASSWORD"),
                List.of("READ"),
                List.of("sensitive"),
                "organization baseline available | organization baseline established | supportingDimensions=ACCESS_HOURS, ACCESS_DAYS, OPERATING_SYSTEMS");
    }
}




