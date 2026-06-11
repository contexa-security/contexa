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
package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityResponse;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.saas.PromptContextAuditForwardingService;
import io.contexa.contexacore.autonomous.saas.SaasBaselineSeedService;
import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.cohort.CohortSeedRuntimeWeightDecision;
import io.contexa.contexacore.autonomous.saas.learning.cohort.CohortSeedRuntimeWeightState;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.quality.Strictness;
import org.mockito.junit.jupiter.MockitoSettings;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AbstractTieredStrategyTest {

    @Mock
    private UnifiedLLMOrchestrator llmOrchestrator;

    @Mock
    private SecurityEventEnricher eventEnricher;

    @Mock
    private SecurityDecisionStandardPromptTemplate promptTemplate;

    @Mock
    private BehaviorVectorService behaviorVectorService;

    @Mock
    private UnifiedVectorService unifiedVectorService;

    @Mock
    private BaselineLearningService baselineLearningService;

    @Mock
    private PromptContextAuthorizationService promptContextAuthorizationService;

    @Mock
    private PromptContextAuditForwardingService promptContextAuditForwardingService;

    private TieredStrategyProperties tieredStrategyProperties;

    private ConcreteStrategy strategy;

    @BeforeEach
    void setUp() {
        tieredStrategyProperties = new TieredStrategyProperties();
        strategy = new ConcreteStrategy(
                eventEnricher,
                promptTemplate,
                behaviorVectorService,
                unifiedVectorService,
                baselineLearningService,
                promptContextAuthorizationService,
                promptContextAuditForwardingService,
                tieredStrategyProperties
        );
    }

    @Test
    @DisplayName("parseJsonResponse should return valid SecurityResponse for well-formed JSON")
    void parseJsonResponse_validJson_returnsSecurityResponse() {
        String json = "{\"riskScore\":0.5,\"confidence\":0.8,\"action\":\"ALLOW\",\"reasoning\":\"Normal activity\"}";

        SecurityResponse response = strategy.callParseJsonResponse(json);

        assertThat(response).isNotNull();
        assertThat(response.getRiskScore()).isEqualTo(0.5);
        assertThat(response.getConfidence()).isEqualTo(0.8);
        assertThat(response.getAction()).isEqualTo("ALLOW");
    }

    @Test
    @DisplayName("parseJsonResponse should return default ESCALATE response for malformed JSON")
    void parseJsonResponse_malformedJson_returnsDefaultEscalateResponse() {
        String malformedJson = "not-a-json-at-all";

        SecurityResponse response = strategy.callParseJsonResponse(malformedJson);

        assertThat(response).isNotNull();
        assertThat(response.getAction()).isEqualTo(ZeroTrustAction.ESCALATE.name());
        assertThat(response.getReasoning()).contains("[AI Native]");
    }

    @Test
    @DisplayName("validateAndFixResponse should clamp riskScore to 0.0-1.0 range")
    void validateAndFixResponse_outOfRangeRiskScore_clampedToValidRange() {
        SecurityResponse response = SecurityResponse.builder()
                .riskScore(1.5)
                .confidence(-0.3)
                .action("ALLOW")
                .reasoning("test")
                .build();

        SecurityResponse validated = strategy.callValidateAndFixResponse(response);

        assertThat(validated.getRiskScore()).isEqualTo(1.0);
        assertThat(validated.getConfidence()).isEqualTo(0.0);
    }

    @Test
    @DisplayName("validateAndFixResponse should preserve values within 0.0-1.0 range")
    void validateAndFixResponse_validRange_preservesValues() {
        SecurityResponse response = SecurityResponse.builder()
                .riskScore(0.5)
                .confidence(0.7)
                .action("BLOCK")
                .reasoning("test")
                .build();

        SecurityResponse validated = strategy.callValidateAndFixResponse(response);

        assertThat(validated.getRiskScore()).isEqualTo(0.5);
        assertThat(validated.getConfidence()).isEqualTo(0.7);
        assertThat(validated.getAction()).isEqualTo("BLOCK");
    }

    @Test
    @DisplayName("createDefaultResponse should return ESCALATE action with AI Native reasoning")
    void createDefaultResponse_returnsEscalateWithAiNativeReasoning() {
        SecurityResponse response = strategy.callCreateDefaultResponse();

        assertThat(response).isNotNull();
        assertThat(response.getAction()).isEqualTo(ZeroTrustAction.ESCALATE.name());
        assertThat(response.getReasoning()).contains("[AI Native]");
        assertThat(response.getReasoning()).contains("TestLayer");
    }

    @Test
    @DisplayName("mapStringToAction should convert ALLOW string to ZeroTrustAction.ALLOW")
    void mapStringToAction_allowString_returnsAllowAction() {
        ZeroTrustAction action = strategy.callMapStringToAction("ALLOW");
        assertThat(action).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("mapStringToAction should convert BLOCK string to ZeroTrustAction.BLOCK")
    void mapStringToAction_blockString_returnsBlockAction() {
        ZeroTrustAction action = strategy.callMapStringToAction("BLOCK");
        assertThat(action).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("mapStringToAction should convert unknown string to ZeroTrustAction.ESCALATE")
    void mapStringToAction_unknownString_returnsEscalate() {
        ZeroTrustAction action = strategy.callMapStringToAction("INVALID_ACTION");
        assertThat(action).isEqualTo(ZeroTrustAction.ESCALATE);
    }

    @Test
    @DisplayName("mapStringToAction should handle null input as ESCALATE")
    void mapStringToAction_nullInput_returnsEscalate() {
        ZeroTrustAction action = strategy.callMapStringToAction(null);
        assertThat(action).isEqualTo(ZeroTrustAction.ESCALATE);
    }

    @Test
    @DisplayName("cacheEscalationContext should store and retrieve session context by eventId")
    void cacheEscalationContext_storesSessionContext_retrievable() {
        String eventId = "test-event-001";
        SecurityDecisionStandardPromptTemplate.SessionContext sessionCtx = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionCtx.setSessionId("session-123");
        sessionCtx.setUserId("user-456");

        AbstractTieredStrategy.cacheEscalationContext(eventId, sessionCtx, null, null);

        SecurityDecisionStandardPromptTemplate.SessionContext cached = AbstractTieredStrategy.getCachedSessionContext(eventId);
        assertThat(cached).isNotNull();
        assertThat(cached.getSessionId()).isEqualTo("session-123");
        assertThat(cached.getUserId()).isEqualTo("user-456");
    }

    @Test
    @DisplayName("cacheEscalationContext should store and retrieve behavior analysis by eventId")
    void cacheEscalationContext_storesBehaviorAnalysis_retrievable() {
        String eventId = "test-event-002";
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorCtx = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorCtx.setBaselineEstablished(true);

        AbstractTieredStrategy.cacheEscalationContext(eventId, null, behaviorCtx, null);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis cached = AbstractTieredStrategy.getCachedBehaviorAnalysis(eventId);
        assertThat(cached).isNotNull();
        assertThat(cached.isBaselineEstablished()).isTrue();
    }

    @Test
    @DisplayName("cacheEscalationContext should store and retrieve RAG documents by eventId")
    void cacheEscalationContext_storesRagDocuments_retrievable() {
        String eventId = "test-event-003";
        List<Document> ragDocs = List.of(new Document("test document content"));

        AbstractTieredStrategy.cacheEscalationContext(eventId, null, null, ragDocs);

        List<Document> cached = AbstractTieredStrategy.getCachedRagDocuments(eventId);
        assertThat(cached).isNotNull();
        assertThat(cached).hasSize(1);
    }

    @Test
    @DisplayName("context retrieval purpose should remain stable across analysis layers")
    void getContextRetrievalPurpose_returnsStableSecurityInvestigationPurpose() {
        assertThat(strategy.getContextRetrievalPurposeForTest()).isEqualTo("security_investigation");
    }

    @Test
    @DisplayName("getCachedSessionContext should return null for null eventId")
    void getCachedSessionContext_nullEventId_returnsNull() {
        SecurityDecisionStandardPromptTemplate.SessionContext cached = AbstractTieredStrategy.getCachedSessionContext(null);
        assertThat(cached).isNull();
    }

    @Test
    @DisplayName("getCachedBehaviorAnalysis should return null for unknown eventId")
    void getCachedBehaviorAnalysis_unknownEventId_returnsNull() {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis cached = AbstractTieredStrategy.getCachedBehaviorAnalysis("non-existent-id");
        assertThat(cached).isNull();
    }

    @Test
    @DisplayName("BaseSessionContext should copy immutable recent actions into mutable storage")
    void baseSessionContext_setRecentActions_shouldCreateMutableCopy() {
        AbstractTieredStrategy.BaseSessionContext sessionContext = new AbstractTieredStrategy.BaseSessionContext();

        sessionContext.setRecentActions(List.of("10:30 | GET /admin/api/security-test/sensitive/resource-001"));
        sessionContext.getRecentActions().add("10:31 | GET /admin/api/security-test/sensitive/resource-001");

        assertThat(sessionContext.getRecentActions())
                .containsExactly(
                        "10:30 | GET /admin/api/security-test/sensitive/resource-001",
                        "10:31 | GET /admin/api/security-test/sensitive/resource-001");
    }

    @Test
    @DisplayName("capturePromptRuntimeTelemetry should copy prompt runtime facts into mutable event metadata")
    void capturePromptRuntimeTelemetry_copiesRuntimeFacts() {
        SecurityEvent event = SecurityEvent.builder()
                .metadata(Map.of("existingKey", "existingValue"))
                .build();
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.withMetadata("promptVersion", "2026.03.27-e0.2");
        response.withMetadata("promptHash", "sha256:test-prompt");
        response.withMetadata("budgetProfile", "CORTEX_L2_STANDARD");
        response.withMetadata("promptEvidenceCompleteness", "SUFFICIENT");
        response.withMetadata("promptSectionSet", List.of("CURRENT_REQUEST", "ROLE_SCOPE"));
        response.withMetadata("officialVerificationPinnedModelId", "qwen3:8b");
        response.withMetadata("officialVerificationTemperature", 0.0d);
        response.withMetadata("officialVerificationTopP", 0.2d);
        response.withMetadata("officialVerificationSeed", 7);
        response.withMetadata("officialVerificationMaxTokens", 96);
        response.withMetadata("officialVerificationDisableRetries", true);

        strategy.capturePromptRuntimeTelemetryForTest(event, response);

        assertThat(event.getMetadata())
                .containsEntry("existingKey", "existingValue")
                .containsEntry("promptVersion", "2026.03.27-e0.2")
                .containsEntry("promptHash", "sha256:test-prompt")
                .containsEntry("budgetProfile", "CORTEX_L2_STANDARD")
                .containsEntry("promptEvidenceCompleteness", "SUFFICIENT")
                .containsEntry("promptRuntimeTelemetryLinked", true)
                .containsEntry("promptRuntimeTelemetryLayer", "TestLayer")
                .containsEntry("officialVerificationPinnedModelId", "qwen3:8b")
                .containsEntry("officialVerificationTemperature", 0.0d)
                .containsEntry("officialVerificationTopP", 0.2d)
                .containsEntry("officialVerificationSeed", 7)
                .containsEntry("officialVerificationMaxTokens", 96)
                .containsEntry("officialVerificationDisableRetries", true);
        assertThat(event.getMetadata().get("promptSectionSet")).isEqualTo(List.of("CURRENT_REQUEST", "ROLE_SCOPE"));
        assertThat(event.getMetadata()).isInstanceOf(LinkedHashMap.class);
    }

    @Test
    @DisplayName("clearPromptRuntimeTelemetry should remove stale prompt runtime facts")
    void clearPromptRuntimeTelemetry_removesStaleFacts() {
        SecurityEvent event = SecurityEvent.builder()
                .metadata(new LinkedHashMap<>(java.util.Map.ofEntries(
                        java.util.Map.entry("promptVersion", "stale-version"),
                        java.util.Map.entry("promptHash", "sha256:stale"),
                        java.util.Map.entry("budgetProfile", "CORTEX_L1_STANDARD"),
                        java.util.Map.entry("officialVerificationDecisionBoundaryMode", "OFFICIAL_VERIFICATION_RUNTIME"),
                        java.util.Map.entry("officialVerificationPinnedModelId", "qwen3:8b"),
                        java.util.Map.entry("officialVerificationTemperature", 0.0d),
                        java.util.Map.entry("officialVerificationTopP", 0.2d),
                        java.util.Map.entry("officialVerificationSeed", 7),
                        java.util.Map.entry("officialVerificationMaxTokens", 96),
                        java.util.Map.entry("promptRuntimeTelemetryLinked", true),
                        java.util.Map.entry("promptRuntimeTelemetryLayer", "Layer1"),
                        java.util.Map.entry("preserveKey", "preserveValue"))))
                .build();

        strategy.clearPromptRuntimeTelemetryForTest(event);

        assertThat(event.getMetadata())
                .doesNotContainKeys(
                        "promptVersion",
                        "promptHash",
                        "budgetProfile",
                        "promptRuntimeTelemetryLinked",
                        "promptRuntimeTelemetryLayer")
                .containsEntry("officialVerificationDecisionBoundaryMode", "OFFICIAL_VERIFICATION_RUNTIME")
                .containsEntry("officialVerificationPinnedModelId", "qwen3:8b")
                .containsEntry("officialVerificationTemperature", 0.0d)
                .containsEntry("officialVerificationTopP", 0.2d)
                .containsEntry("officialVerificationSeed", 7)
                .containsEntry("officialVerificationMaxTokens", 96)
                .containsEntry("preserveKey", "preserveValue");
    }

    @Test
    @DisplayName("buildSecurityDecisionRequest should prefer explicit prompt budget profile from event metadata")
    void buildSecurityDecisionRequest_shouldPreferExplicitPromptBudgetProfileFromEventMetadata() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-budget-profile")
                .metadata(new LinkedHashMap<>(Map.of("promptBudgetProfile", "CORTEX_L1_COMPACT")))
                .build();

        SecurityDecisionRequest request = strategy.buildSecurityDecisionRequestForTest(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(request.getParameter("promptBudgetProfile", String.class)).isEqualTo("CORTEX_L1_COMPACT");
    }

    @Test
    @DisplayName("buildSecurityDecisionRequest should use configured layer1 default budget profile when no override exists")
    void buildSecurityDecisionRequest_shouldUseConfiguredLayer1DefaultBudgetProfile() {
        tieredStrategyProperties.getLayer1().setDefaultBudgetProfile("CORTEX_L1_DECISION_COMPACT");
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-budget-profile-default-layer1")
                .metadata(new LinkedHashMap<>())
                .build();

        SecurityDecisionRequest request = strategy.buildSecurityDecisionRequestForTest(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(request.getParameter("promptBudgetProfile", String.class))
                .isEqualTo(PromptBudgetProfile.CORTEX_L1_DECISION_COMPACT.profileKey());
    }

    @Test
    @DisplayName("buildSecurityDecisionRequest should use configured layer2 default budget profile for layer2 strategies")
    void buildSecurityDecisionRequest_shouldUseConfiguredLayer2DefaultBudgetProfile() {
        tieredStrategyProperties.getLayer2().setDefaultBudgetProfile("CORTEX_L2_COMPACT");
        Layer2ConcreteStrategy layer2Strategy = new Layer2ConcreteStrategy(
                eventEnricher,
                promptTemplate,
                behaviorVectorService,
                unifiedVectorService,
                baselineLearningService,
                promptContextAuthorizationService,
                promptContextAuditForwardingService,
                tieredStrategyProperties
        );
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-budget-profile-default-layer2")
                .metadata(new LinkedHashMap<>())
                .build();

        SecurityDecisionRequest request = layer2Strategy.buildSecurityDecisionRequestForTest(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(request.getParameter("promptBudgetProfile", String.class))
                .isEqualTo(PromptBudgetProfile.CORTEX_L2_COMPACT.profileKey());
    }
    @Test
    @DisplayName("buildSecurityDecisionRequest should copy official verification runtime options into AI request parameters")
    void buildSecurityDecisionRequest_shouldCopyOfficialVerificationRuntimeOptions() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-official-runtime")
                .metadata(new LinkedHashMap<>(Map.of(
                        "scenario", "OFFICIAL_VERIFICATION_CDC_RESOURCE_SURGE",
                        "promptBudgetProfile", "CORTEX_L1_COMPACT",
                        "officialVerificationPinnedModelId", "qwen3:8b",
                        "officialVerificationTemperature", 0.0d,
                        "officialVerificationTopP", 0.2d,
                        "officialVerificationSeed", 7,
                        "officialVerificationMaxTokens", 96,
                        "officialVerificationDisableRetries", true,
                        "officialVerificationDisableOllamaThinking", true)))
                .build();

        SecurityDecisionRequest request = strategy.buildSecurityDecisionRequestForTest(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(request.getParameter("promptBudgetProfile", String.class)).isEqualTo("CORTEX_L1_COMPACT");
        assertThat(request.getParameter("officialVerificationPinnedModelId", String.class)).isEqualTo("qwen3:8b");
        assertThat(request.getParameter("officialVerificationTemperature", Double.class)).isEqualTo(0.0d);
        assertThat(request.getParameter("officialVerificationTopP", Double.class)).isEqualTo(0.2d);
        assertThat(request.getParameter("officialVerificationSeed", Integer.class)).isEqualTo(7);
        assertThat(request.getParameter("officialVerificationMaxTokens", Integer.class)).isEqualTo(96);
        assertThat(request.getParameter("officialVerificationDisableRetries", Boolean.class)).isTrue();
        assertThat(request.getParameter("officialVerificationDisableOllamaThinking", Boolean.class)).isTrue();
        assertThat(request.getParameter("officialVerificationDecisionBoundaryMode", String.class))
                .isEqualTo("OFFICIAL_VERIFICATION_RUNTIME");
    }

    @Test
    @DisplayName("buildSecurityDecisionRequest should disable native structured output for explicitly disabled prompt profiles")
    void buildSecurityDecisionRequest_shouldDisableNativeStructuredOutputForDisabledProfile() {
        tieredStrategyProperties.getPromptRuntime()
                .setNativeStructuredOutputDisabledProfiles(List.of("CORTEX_L1_COMPACT"));
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-native-disabled-profile")
                .metadata(new LinkedHashMap<>(Map.of("promptBudgetProfile", "CORTEX_L1_COMPACT")))
                .build();

        SecurityDecisionRequest request = strategy.buildSecurityDecisionRequestForTest(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(request.getParameter("nativeStructuredOutputEnabled", Boolean.class)).isFalse();
        assertThat(request.getParameter("structuredOutputMode", String.class))
                .isEqualTo(StructuredOutputMode.VALIDATED_CONVERTER.name());
    }

    @Test
    @DisplayName("buildSecurityDecisionRequest should keep native structured output enabled for allowed prompt profiles")
    void buildSecurityDecisionRequest_shouldKeepNativeStructuredOutputEnabledForAllowedProfile() {
        tieredStrategyProperties.getPromptRuntime()
                .setNativeStructuredOutputDisabledProfiles(List.of("CORTEX_L2_EXPERT_STRICT"));
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-native-enabled-profile")
                .metadata(new LinkedHashMap<>(Map.of("promptBudgetProfile", "CORTEX_L1_INTERACTIVE_STRICT")))
                .build();

        SecurityDecisionRequest request = strategy.buildSecurityDecisionRequestForTest(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(request.getParameter("nativeStructuredOutputEnabled", Boolean.class)).isTrue();
        assertThat(request.getParameter("structuredOutputMode", String.class))
                .isIn(StructuredOutputMode.NATIVE_STRUCTURED.name(), StructuredOutputMode.VALIDATED_CONVERTER.name());
    }

    @Test
    @DisplayName("searchRelatedContextBase should capture prompt audit fallback when vector search fails")
    void searchRelatedContextBase_vectorFailure_capturesPromptAuditFallback() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-vector-failure")
                .userId("admin")
                .sourceIp("192.168.1.100")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                .metadata(new LinkedHashMap<>(Map.of("requestId", "request-vector-failure")))
                .build();
        when(eventEnricher.getTargetResource(event)).thenReturn(Optional.of("/admin/api/security-test/sensitive/resource-001"));
        when(unifiedVectorService.searchSimilar(any(SearchRequest.class)))
                .thenThrow(new RuntimeException("Similarity search failed"));

        List<Document> result = strategy.callSearchRelatedContextBase(event, 3, 0.7d);

        assertThat(result).isEmpty();
        ArgumentCaptor<String> retrievalPurposeCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<AuthorizedPromptContext> promptContextCaptor = ArgumentCaptor.forClass(AuthorizedPromptContext.class);
        verify(promptContextAuditForwardingService, times(1))
                .capture(org.mockito.ArgumentMatchers.same(event), retrievalPurposeCaptor.capture(), promptContextCaptor.capture());
        assertThat(retrievalPurposeCaptor.getValue()).isEqualTo("security_investigation");
        assertThat(promptContextCaptor.getValue().documents()).isEmpty();
        assertThat(promptContextCaptor.getValue().requestedDocumentCount()).isEqualTo(3);
        assertThat(promptContextCaptor.getValue().deniedReasons())
                .contains("VECTOR_STORE_SEARCH_FAILED", "RuntimeException", "Similarity search failed");
    }

    @Test
    @DisplayName("searchRelatedContextBase should capture prompt audit fallback when userId is missing")
    void searchRelatedContextBase_missingUserId_capturesPromptAuditFallback() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-user-missing")
                .userId("unknown")
                .sourceIp("192.168.1.100")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                .metadata(new LinkedHashMap<>(Map.of("requestId", "request-user-missing")))
                .build();
        when(eventEnricher.getTargetResource(event)).thenReturn(Optional.of("/admin/api/security-test/sensitive/resource-001"));

        List<Document> result = strategy.callSearchRelatedContextBase(event, 2, 0.7d);

        assertThat(result).isEmpty();
        verify(unifiedVectorService, times(0)).searchSimilar(any(SearchRequest.class));
        ArgumentCaptor<String> retrievalPurposeCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<AuthorizedPromptContext> promptContextCaptor = ArgumentCaptor.forClass(AuthorizedPromptContext.class);
        verify(promptContextAuditForwardingService, times(1))
                .capture(org.mockito.ArgumentMatchers.same(event), retrievalPurposeCaptor.capture(), promptContextCaptor.capture());
        assertThat(retrievalPurposeCaptor.getValue()).isEqualTo("security_investigation");
        assertThat(promptContextCaptor.getValue().documents()).isEmpty();
        assertThat(promptContextCaptor.getValue().requestedDocumentCount()).isEqualTo(2);
        assertThat(promptContextCaptor.getValue().deniedReasons()).contains("USER_ID_MISSING");
    }

    @Test
    @DisplayName("searchRelatedContextBase should use same-user baseline fallback when strict RAG search returns zero")
    void searchRelatedContextBase_zeroStrictResults_usesSameUserBaselineFallback() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-same-user-baseline-fallback")
                .userId("persona_fin_lead")
                .sourceIp("0:0:0:0:0:0:0:1")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/148.0.0.0 Safari/537.36")
                .metadata(new LinkedHashMap<>(Map.of(
                        "organizationId", "demo-org",
                        "tenantId", "demo",
                        "resourceId", "resource-001",
                        "resourceType", "normal",
                        "httpMethod", "GET",
                        "authenticationType", "PASSWORD")))
                .build();
        when(eventEnricher.getTargetResource(event))
                .thenReturn(Optional.of("/admin/api/enterprise/verification/runtime/probe/normal/resource-001"));
        when(baselineLearningService.describeBaselineMaturity("persona_fin_lead", "demo-org"))
                .thenReturn(new BaselineLearningService.BaselineMaturitySnapshot(
                        true,
                        true,
                        true,
                        true,
                        true,
                        List.of("ACCESS_HOURS", "NETWORKS", "BROWSERS")));
        Document learnedContext = new Document(
                "User accessed demo baseline learning cycle=1 resource=normal auth=PASSWORD via GET from 10.10.0.20 using Chrome/120.",
                Map.of(
                        "userId", "persona_fin_lead",
                        "documentType", "behavior",
                        "retrievalPurpose", "security_investigation"));
        when(unifiedVectorService.searchSimilar(any(SearchRequest.class)))
                .thenAnswer(invocation -> {
                    SearchRequest req = invocation.getArgument(0);
                    if (req != null && req.getQuery() != null && req.getQuery().contains("user: persona_fin_lead")) {
                        return List.of(learnedContext);
                    }
                    return List.of();
                });
        when(promptContextAuthorizationService.authorize(
                any(SecurityEvent.class),
                any(),
                org.mockito.ArgumentMatchers.<List<Document>>any()))
                .thenAnswer(invocation -> {
                    List<Document> documents = invocation.getArgument(2);
                    return new AuthorizedPromptContext(
                            documents,
                            documents.size(),
                            documents.size(),
                            0,
                            "security_investigation",
                            List.of());
                });

        List<Document> result = strategy.callSearchRelatedContextBase(event, 3, 0.7d);

        assertThat(result).containsExactly(learnedContext);
        ArgumentCaptor<SearchRequest> searchRequestCaptor = ArgumentCaptor.forClass(SearchRequest.class);
        verify(unifiedVectorService, times(4)).searchSimilar(searchRequestCaptor.capture());
        SearchRequest fallbackRequest = searchRequestCaptor.getAllValues().stream()
                .filter(req -> req.getSimilarityThreshold() == 0.0d)
                .findFirst()
                .orElseThrow(() -> new AssertionError("Could not find baseline fallback request with threshold 0.0"));
        assertThat(fallbackRequest.getQuery())
                .contains("user: persona_fin_lead", "purpose: security_investigation", "action: READ")
                .doesNotContain("Chrome/148")
                .doesNotContain("/admin/api/enterprise/verification/runtime/probe/normal/resource-001");
        assertThat(fallbackRequest.getSimilarityThreshold()).isEqualTo(0.0d);
        assertThat(event.getMetadata())
                .containsEntry("ragRetrievalState", "AVAILABLE")
                .containsEntry("relatedDocumentCount", 1)
                .containsEntry("ragProjectedToFinalPrompt", true);
    }
    @Test
    @DisplayName("enrichBehaviorAnalysisWithBaselineSupport should apply cohort seed runtime weight decision")
    void enrichBehaviorAnalysisWithBaselineSupport_appliesCohortSeedRuntimeWeightDecision() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-cohort-seed-weight")
                .userId("user-123")
                .metadata(new LinkedHashMap<>())
                .build();
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        BaselineSeedSnapshot seedSnapshot = new BaselineSeedSnapshot(
                "tenant-a", true, true, true, "FINTECH_APAC_LARGE", "FINTECH", "APAC", 18, 420L,
                List.of(9, 10), List.of(1, 2), List.of("WINDOWS"), Map.of(), Map.of(), Map.of(),
                java.time.LocalDate.of(2026, 4, 8), java.time.LocalDateTime.of(2026, 4, 8, 12, 0));
        SaasBaselineSeedService baselineSeedService = org.mockito.Mockito.mock(SaasBaselineSeedService.class);
        when(baselineLearningService.getBaseline("user-123")).thenReturn(null);
        when(baselineLearningService.describeBaselineMaturity("user-123", null))
                .thenReturn(new BaselineLearningService.BaselineMaturitySnapshot(
                        true,
                        true,
                        true,
                        true,
                        true,
                        List.of("ACCESS_HOURS", "OPERATING_SYSTEMS")));
        when(baselineSeedService.resolvePromptSeed(true, true))
                .thenReturn(new CohortSeedRuntimeWeightDecision(
                        seedSnapshot,
                        true,
                        0.15d,
                        CohortSeedRuntimeWeightState.DEGRADED_ESTABLISHED_BASELINES,
                        List.of("Both local baselines are established.", "Runtime weight 0.15 applies.")));
        strategy.enrichBehaviorAnalysisWithBaselineSupportForTest(behaviorAnalysis, event, baselineSeedService);
        assertThat(behaviorAnalysis.isCohortSeedApplied()).isTrue();
        assertThat(behaviorAnalysis.getCohortBaselineSeed()).isEqualTo(seedSnapshot);
        assertThat(behaviorAnalysis.getCohortSeedWeight()).isEqualTo(0.15d);
        assertThat(behaviorAnalysis.getCohortSeedWeightState()).isEqualTo("DEGRADED_ESTABLISHED_BASELINES");
        assertThat(behaviorAnalysis.getCohortSeedPolicyFacts())
                .containsExactly("Both local baselines are established.", "Runtime weight 0.15 applies.");
        assertThat(event.getMetadata())
                .containsEntry("baselineSeedApplied", true)
                .containsEntry("baselineSeedWeight", 0.15d)
                .containsEntry("baselineSeedWeightState", "DEGRADED_ESTABLISHED_BASELINES");
    }

    @Test
    @DisplayName("enrichBehaviorAnalysisWithBaselineSupport should set typed service unavailable evidence when baseline service is missing")
    void enrichBehaviorAnalysisWithBaselineSupport_missingService_setsTypedUnavailableEvidence() {
        ConcreteStrategy strategyWithoutBaselineService = new ConcreteStrategy(
                eventEnricher,
                promptTemplate,
                behaviorVectorService,
                unifiedVectorService,
                null,
                promptContextAuthorizationService,
                promptContextAuditForwardingService,
                tieredStrategyProperties
        );
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        SecurityEvent event = SecurityEvent.builder()
                .userId("alice")
                .metadata(new LinkedHashMap<>())
                .build();

        strategyWithoutBaselineService.enrichBehaviorAnalysisWithBaselineSupportForTest(behaviorAnalysis, event, null);

        assertThat(behaviorAnalysis.getPersonalBaselineEvidence()).isNotNull();
        assertThat(behaviorAnalysis.getPersonalBaselineEvidence().status())
                .isEqualTo(BaselineEvidenceStatus.SERVICE_UNAVAILABLE);
        assertThat(behaviorAnalysis.getSupportingBaselineEvidence()).isNotNull();
        assertThat(behaviorAnalysis.getSupportingBaselineEvidence().status())
                .isEqualTo(BaselineEvidenceStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    @DisplayName("enrichBehaviorAnalysisWithBaselineSupport should set typed missing-user-id evidence when userId is absent")
    void enrichBehaviorAnalysisWithBaselineSupport_missingUserId_setsTypedMissingUserEvidence() {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        SecurityEvent event = SecurityEvent.builder()
                .metadata(new LinkedHashMap<>())
                .build();

        strategy.enrichBehaviorAnalysisWithBaselineSupportForTest(behaviorAnalysis, event, null);

        assertThat(behaviorAnalysis.getPersonalBaselineEvidence()).isNotNull();
        assertThat(behaviorAnalysis.getPersonalBaselineEvidence().status())
                .isEqualTo(BaselineEvidenceStatus.MISSING_USER_ID);
        assertThat(behaviorAnalysis.getSupportingBaselineEvidence()).isNotNull();
        assertThat(behaviorAnalysis.getSupportingBaselineEvidence().status())
                .isEqualTo(BaselineEvidenceStatus.MISSING_USER_ID);
    }

    // -- Concrete test implementation of the abstract class --

    private static class ConcreteStrategy extends AbstractTieredStrategy {

        ConcreteStrategy(SecurityEventEnricher eventEnricher,
                         SecurityDecisionStandardPromptTemplate promptTemplate,
                         BehaviorVectorService behaviorVectorService,
                         UnifiedVectorService unifiedVectorService,
                         BaselineLearningService baselineLearningService,
                         PromptContextAuthorizationService promptContextAuthorizationService,
                         PromptContextAuditForwardingService promptContextAuditForwardingService,
                         TieredStrategyProperties tieredStrategyProperties) {
            super(eventEnricher, promptTemplate,
                    behaviorVectorService, unifiedVectorService,
                    baselineLearningService,
                    promptContextAuthorizationService,
                    promptContextAuditForwardingService,
                    tieredStrategyProperties);
        }

        @Override
        protected String getLayerName() {
            return "TestLayer";
        }

        @Override
        public ThreatAssessment evaluate(SecurityEvent event) {
            return null;
        }

        // Expose protected methods for testing
        SecurityResponse callParseJsonResponse(String json) {
            return parseJsonResponse(json);
        }

        SecurityResponse callValidateAndFixResponse(SecurityResponse response) {
            return validateAndFixResponse(response);
        }

        SecurityResponse callCreateDefaultResponse() {
            return createDefaultResponse();
        }

        String getContextRetrievalPurposeForTest() {
            return getContextRetrievalPurpose();
        }

        ZeroTrustAction callMapStringToAction(String action) {
            return mapStringToAction(action);
        }

        void capturePromptRuntimeTelemetryForTest(SecurityEvent event, SecurityDecisionResponse response) {
            capturePromptRuntimeTelemetry(event, response);
        }

        void clearPromptRuntimeTelemetryForTest(SecurityEvent event) {
            clearPromptRuntimeTelemetry(event);
        }

        List<Document> callSearchRelatedContextBase(SecurityEvent event, int topK, double similarityThreshold) {
            return searchRelatedContextBase(event, topK, similarityThreshold);
        }
        void enrichBehaviorAnalysisWithBaselineSupportForTest(
                SecurityDecisionStandardPromptTemplate.BehaviorAnalysis context,
                SecurityEvent event,
                SaasBaselineSeedService baselineSeedService) {
            enrichBehaviorAnalysisWithBaselineSupport(context, event, baselineSeedService);
        }
        SecurityDecisionRequest buildSecurityDecisionRequestForTest(
                SecurityEvent event,
                SecurityDecisionStandardPromptTemplate.SessionContext sessionContext,
                SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis,
                List<Document> relatedDocuments) {
            return buildSecurityDecisionRequest(event, sessionContext, behaviorAnalysis, relatedDocuments);
        }
    }

    private static class Layer2ConcreteStrategy extends ConcreteStrategy {

        Layer2ConcreteStrategy(SecurityEventEnricher eventEnricher,
                               SecurityDecisionStandardPromptTemplate promptTemplate,
                               BehaviorVectorService behaviorVectorService,
                               UnifiedVectorService unifiedVectorService,
                               BaselineLearningService baselineLearningService,
                               PromptContextAuthorizationService promptContextAuthorizationService,
                               PromptContextAuditForwardingService promptContextAuditForwardingService,
                               TieredStrategyProperties tieredStrategyProperties) {
            super(eventEnricher,
                    promptTemplate,
                    behaviorVectorService,
                    unifiedVectorService,
                    baselineLearningService,
                    promptContextAuthorizationService,
                    promptContextAuditForwardingService,
                    tieredStrategyProperties);
        }

        @Override
        protected String getLayerName() {
            return "Layer2-Test";
        }
    }
}

