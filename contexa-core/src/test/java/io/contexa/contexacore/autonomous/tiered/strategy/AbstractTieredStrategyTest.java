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

import java.time.Instant;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityResponse;
import io.contexa.contexacore.ThreatAssessment;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.cohort.CohortSeedRuntimeWeightDecision;
import io.contexa.contexacore.autonomous.saas.learning.cohort.CohortSeedRuntimeWeightState;
import io.contexa.contexacore.autonomous.saas.PromptContextAuditForwardingService;
import io.contexa.contexacore.autonomous.saas.SaasBaselineSeedService;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptSections;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.PolicySatisfaction;
import io.contexa.contexacore.autonomous.context.support.PastRecordCounts;
import io.contexa.contexacore.autonomous.context.support.PastRecordGroup;
import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.context.support.PastRecordScope;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.quality.Strictness;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.Embedding;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingRequest;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.SimpleVectorStore;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;


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
    @DisplayName("the strategy reads a change of device or network within the session the event carries (W2-14)")
    void hydrate_readsTheSessionsChangedPartsFromTheEvent() {
        SecurityEvent event = SecurityEvent.builder().eventId("evt-moved").build();
        event.addMetadata("sessionDeviceChange", "Chrome/140 on WINDOWS -> Safari/17 on MAC");
        event.addMetadata("sessionNetworkChange", "10.40.12.0/24 -> 203.0.113.0/24");
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis analysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();

        strategy.hydrateBehaviorAnalysisRuntimeFacts(analysis, event);

        assertThat(analysis.getSessionDeviceChange()).isEqualTo("Chrome/140 on WINDOWS -> Safari/17 on MAC");
        assertThat(analysis.getSessionNetworkChange()).isEqualTo("10.40.12.0/24 -> 203.0.113.0/24");
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
    @DisplayName("BaseSessionContext measures a session from its first event to its latest one on the event clock")
    void baseSessionContext_measuresTheSessionOnTheEventClock() {
        AbstractTieredStrategy.BaseSessionContext sessionContext = new AbstractTieredStrategy.BaseSessionContext();
        Instant start = Instant.parse("2026-09-30T03:15:00Z");

        sessionContext.setStartTime(start);
        sessionContext.recordEventTime(start.plusSeconds(360));
        sessionContext.recordEventTime(start.plusSeconds(120));

        // A late, older event does not shorten the session; the server clock plays no part.
        assertThat(sessionContext.getSessionDuration()).isEqualTo(6);
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
                .doesNotContainKeys("officialVerificationPinnedModelId", "officialVerificationTemperature", "officialVerificationTopP", "officialVerificationSeed", "officialVerificationMaxTokens", "officialVerificationDisableRetries");
        assertThat(event.getMetadata().get("promptSectionSet")).isEqualTo(List.of("CURRENT_REQUEST", "ROLE_SCOPE"));
        assertThat(event.getMetadata()).isInstanceOf(LinkedHashMap.class);
    }

    @Test
    @DisplayName("clearPromptRuntimeTelemetry should remove stale prompt runtime facts")
    void clearPromptRuntimeTelemetry_removesStaleFacts() {
        SecurityEvent event = SecurityEvent.builder()
                .metadata(new LinkedHashMap<>(Map.ofEntries(
                        Map.entry("promptVersion", "stale-version"),
                        Map.entry("promptHash", "sha256:stale"),
                        Map.entry("budgetProfile", "CORTEX_L1_STANDARD"),
                        Map.entry("officialVerificationDecisionBoundaryMode", "OFFICIAL_VERIFICATION_RUNTIME"),
                        Map.entry("officialVerificationPinnedModelId", "qwen3:8b"),
                        Map.entry("officialVerificationTemperature", 0.0d),
                        Map.entry("officialVerificationTopP", 0.2d),
                        Map.entry("officialVerificationSeed", 7),
                        Map.entry("officialVerificationMaxTokens", 96),
                        Map.entry("promptRuntimeTelemetryLinked", true),
                        Map.entry("promptRuntimeTelemetryLayer", "Layer1"),
                        Map.entry("preserveKey", "preserveValue"))))
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
    @DisplayName("buildSecurityDecisionRequest should ignore prompt budget profile from event metadata")
    void buildSecurityDecisionRequest_shouldIgnorePromptBudgetProfileFromEventMetadata() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-budget-profile")
                .metadata(new LinkedHashMap<>(Map.of("promptBudgetProfile", "CORTEX_L1_COMPACT")))
                .build();

        SecurityDecisionRequest request = strategy.buildSecurityDecisionRequestForTest(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(request.getParameter("promptBudgetProfile", String.class))
                .isEqualTo(PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT.profileKey());
    }

    @Test
    @DisplayName("buildSecurityDecisionRequest should use configured layer1 default budget profile when no override exists")
    void buildSecurityDecisionRequest_shouldUseConfiguredLayer1DefaultBudgetProfile() {
        tieredStrategyProperties.getLayer1().setDefaultBudgetProfile("CORTEX_L1_INTERACTIVE_STRICT");
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
                .isEqualTo(PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT.profileKey());
    }

    @Test
    @DisplayName("buildSecurityDecisionRequest should use configured layer2 default budget profile for layer2 strategies")
    void buildSecurityDecisionRequest_shouldUseConfiguredLayer2DefaultBudgetProfile() {
        tieredStrategyProperties.getLayer2().setDefaultBudgetProfile("CORTEX_L2_EXPERT_STRICT");
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
                .isEqualTo(PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT.profileKey());
    }
    @Test
    @DisplayName("buildSecurityDecisionRequest should apply layer OpenAI runtime options for normal runtime decisions")
    void buildSecurityDecisionRequest_shouldApplyLayerOpenAiRuntimeOptionsForNormalRuntimeDecision() {
        tieredStrategyProperties.getLayer1().setOpenAiReasoningEffort("minimal");
        tieredStrategyProperties.getLayer1().setOpenAiVerbosity("low");
        tieredStrategyProperties.getLayer1().setMaxOutputTokens(256);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-runtime-openai-options")
                .metadata(new LinkedHashMap<>())
                .build();

        SecurityDecisionRequest request = strategy.buildSecurityDecisionRequestForTest(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(request.getParameter("openAiReasoningEffort", String.class)).isEqualTo("minimal");
        assertThat(request.getParameter("openAiVerbosity", String.class)).isEqualTo("low");
        assertThat(request.getParameter("maxTokens", Integer.class)).isNull();
        assertThat(request.getParameter("platformSecurityDecisionMaxTokens", Integer.class)).isEqualTo(256);
    }

    /** P3-EXTRA-9: the Layer1 model call limit travels as a platform parameter to the provider call. */
    @Test
    void theLayerOneModelCallLimitTravelsWithTheRequest() {
        tieredStrategyProperties.getLayer1().getTimeout().setLlmMs(1500);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-call-limit")
                .metadata(new LinkedHashMap<>())
                .build();

        SecurityDecisionRequest request = strategy.buildSecurityDecisionRequestForTest(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(request.getParameter("platformSecurityDecisionCallTimeoutMs", Long.class)).isEqualTo(1500L);
    }

    /**
     * R4-L4: the former verification runtime keys are event text; they neither turn the layer OpenAI options off nor
     * travel into the request.
     */
    @Test
    void theFormerVerificationRuntimeKeysNeitherSkipTheLayerOptionsNorReachTheRequest() {
        tieredStrategyProperties.getLayer1().setOpenAiReasoningEffort("minimal");
        tieredStrategyProperties.getLayer1().setOpenAiVerbosity("low");
        tieredStrategyProperties.getLayer1().setMaxOutputTokens(256);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-former-verification-keys")
                .metadata(new LinkedHashMap<>(Map.of(
                        "officialVerificationPinnedModelId", "qwen3:8b",
                        "officialVerificationMaxTokens", 96,
                        "officialVerificationDecisionBoundaryMode", "OFFICIAL_VERIFICATION_RUNTIME")))
                .build();

        SecurityDecisionRequest request = strategy.buildSecurityDecisionRequestForTest(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(request.getParameter("openAiReasoningEffort", String.class)).isEqualTo("minimal");
        assertThat(request.getParameter("platformSecurityDecisionMaxTokens", Integer.class)).isEqualTo(256);
        assertThat(request.getParameter("officialVerificationPinnedModelId", String.class)).isNull();
        assertThat(request.getParameter("officialVerificationMaxTokens", Integer.class)).isNull();
        assertThat(request.getParameter("officialVerificationDecisionBoundaryMode", String.class)).isNull();
    }

    @Test
    @DisplayName("buildSecurityDecisionRequest should disable native structured output for explicitly disabled prompt profiles")
    void buildSecurityDecisionRequest_shouldDisableNativeStructuredOutputForDisabledProfile() {
        tieredStrategyProperties.getPromptRuntime()
                .setNativeStructuredOutputDisabledProfiles(List.of("CORTEX_L1_INTERACTIVE_STRICT"));
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

    /** W4-2: a v20 request with native structured output asks the provider to enforce the output contract v3. */
    @Test
    void aV20RequestWithNativeStructuredOutputCarriesTheOutputContractSchema() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-w42-native")
                .metadata(new LinkedHashMap<>(Map.of("structuredOutputMode", StructuredOutputMode.NATIVE_STRUCTURED.name())))
                .build();
        when(promptTemplate.promptBundle(event)).thenReturn(SecurityDecisionPromptBundles.V20);

        SecurityDecisionRequest request = strategy.buildSecurityDecisionRequestForTest(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of());

        assertThat(request.getParameter(ExecutionContext.OUTPUT_SCHEMA, String.class))
                .isEqualTo(SecurityDecisionOutputContract.providerSchema());
    }

    /** W4-2: the v19 bundle keeps its format, and without native structured output the system text states the schema. */
    @Test
    void aV19RequestOrOneWithoutNativeStructuredOutputCarriesNoSchema() {
        SecurityEvent v19 = SecurityEvent.builder()
                .eventId("event-w42-v19")
                .metadata(new LinkedHashMap<>(Map.of("structuredOutputMode", StructuredOutputMode.NATIVE_STRUCTURED.name())))
                .build();
        SecurityEvent converter = SecurityEvent.builder()
                .eventId("event-w42-converter")
                .metadata(new LinkedHashMap<>(Map.of("structuredOutputMode", StructuredOutputMode.VALIDATED_CONVERTER.name())))
                .build();
        when(promptTemplate.promptBundle(v19)).thenReturn(SecurityDecisionPromptBundles.DEFAULT);
        when(promptTemplate.promptBundle(converter)).thenReturn(SecurityDecisionPromptBundles.V20);

        for (SecurityEvent event : List.of(v19, converter)) {
            SecurityDecisionRequest request = strategy.buildSecurityDecisionRequestForTest(
                    event,
                    new SecurityDecisionStandardPromptTemplate.SessionContext(),
                    new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                    List.of());

            assertThat(request.getParameter(ExecutionContext.OUTPUT_SCHEMA, String.class)).as(event.getEventId()).isNull();
        }
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
                .capture(ArgumentMatchers.same(event), retrievalPurposeCaptor.capture(), promptContextCaptor.capture());
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
                .capture(ArgumentMatchers.same(event), retrievalPurposeCaptor.capture(), promptContextCaptor.capture());
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
                ArgumentMatchers.<List<Document>>any()))
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
        assertThat(String.valueOf(fallbackRequest.getFilterExpression()))
                .contains("resourceId", "resource-001")
                .doesNotContain("/admin/api/enterprise/verification/runtime/probe/normal/resource-001");
        assertThat(event.getMetadata())
                .containsEntry("ragRetrievalState", "AVAILABLE")
                .containsEntry("relatedDocumentCount", 1)
                .containsEntry("ragProjectedToFinalPrompt", true);
    }

    @Test
    @DisplayName("searchRelatedContextBase should name the request's action as the context gives it")
    void searchRelatedContextBase_namesTheActionTheContextGivesTheRequest() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-export-action")
                .userId("persona_fin_lead")
                .metadata(new LinkedHashMap<>(Map.of(
                        "organizationId", "demo-org",
                        "tenantId", "demo",
                        "httpMethod", "POST",
                        "protectableMethod", "io.contexa.example.BusinessOperations.exportDocuments")))
                .build();
        when(eventEnricher.getTargetResource(event)).thenReturn(Optional.of("/api/projects/GB-500/exports"));
        when(unifiedVectorService.searchSimilar(any(SearchRequest.class))).thenReturn(List.of());
        when(promptContextAuthorizationService.authorize(
                any(SecurityEvent.class),
                any(),
                ArgumentMatchers.<List<Document>>any()))
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

        strategy.callSearchRelatedContextBase(event, 3, 0.7d);

        ArgumentCaptor<SearchRequest> searchRequestCaptor = ArgumentCaptor.forClass(SearchRequest.class);
        verify(unifiedVectorService, Mockito.atLeastOnce()).searchSimilar(searchRequestCaptor.capture());
        // A bulk export sent as a POST is searched as an export, the family stored with past decisions, not a write.
        assertThat(searchRequestCaptor.getAllValues()).extracting(SearchRequest::getQuery)
                .allSatisfy(query -> assertThat(query).doesNotContain("action: WRITE"))
                .anySatisfy(query -> assertThat(query).contains("action: EXPORT"));
    }

    @Test
    @DisplayName("searchRelatedContextBase should name the request's path family as the host's URL template")
    void searchRelatedContextBase_namesThePathFamilyAsTheHostsUrlTemplate() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-export-path-family")
                .userId("persona_fin_lead")
                .metadata(new LinkedHashMap<>(Map.of(
                        "organizationId", "demo-org",
                        "tenantId", "demo",
                        "httpMethod", "POST",
                        "protectableResourceUrl", "/api/projects/{projectKey}/exports")))
                .build();
        when(eventEnricher.getTargetResource(event)).thenReturn(Optional.of("/api/projects/GB-500/exports"));
        when(unifiedVectorService.searchSimilar(any(SearchRequest.class))).thenReturn(List.of());
        when(promptContextAuthorizationService.authorize(
                any(SecurityEvent.class),
                any(),
                ArgumentMatchers.<List<Document>>any()))
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

        strategy.callSearchRelatedContextBase(event, 3, 0.7d);

        ArgumentCaptor<SearchRequest> searchRequestCaptor = ArgumentCaptor.forClass(SearchRequest.class);
        verify(unifiedVectorService, Mockito.atLeastOnce()).searchSimilar(searchRequestCaptor.capture());
        // Past records of any project's export match the query, as the stored records name the template (W2-2).
        assertThat(searchRequestCaptor.getAllValues()).extracting(SearchRequest::getQuery)
                .allSatisfy(query -> assertThat(query).doesNotContain("pathFamily: /api/projects/GB-500"))
                .anySatisfy(query -> assertThat(query).contains("pathFamily: /api/projects/{projectKey}/exports"));
    }

    @Test
    @DisplayName("searchRelatedContextBase should never name a family hint's word as the request's class (W2-10)")
    void searchRelatedContextBase_neverNamesAFamilyHintAsTheClass() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-release-class")
                .userId("persona_fin_lead")
                .metadata(new LinkedHashMap<>(Map.of(
                        "organizationId", "demo-org",
                        "tenantId", "demo",
                        "httpMethod", "GET",
                        "resourceFamily", "PUBLIC_RELEASES")))
                .build();
        when(eventEnricher.getTargetResource(event)).thenReturn(Optional.of("/api/releases/R-1"));
        when(unifiedVectorService.searchSimilar(any(SearchRequest.class))).thenReturn(List.of());
        when(promptContextAuthorizationService.authorize(
                any(SecurityEvent.class),
                any(),
                ArgumentMatchers.<List<Document>>any()))
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

        strategy.callSearchRelatedContextBase(event, 3, 0.7d);

        ArgumentCaptor<SearchRequest> searchRequestCaptor = ArgumentCaptor.forClass(SearchRequest.class);
        verify(unifiedVectorService, Mockito.atLeastOnce()).searchSimilar(searchRequestCaptor.capture());
        assertThat(searchRequestCaptor.getAllValues()).extracting(SearchRequest::getQuery)
                .allSatisfy(query -> assertThat(query).doesNotContain("resourceFamily: PUBLIC"));
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
                LocalDate.of(2026, 4, 8), LocalDateTime.of(2026, 4, 8, 12, 0));
        SaasBaselineSeedService baselineSeedService = Mockito.mock(SaasBaselineSeedService.class);
        BaselineLearningService.BaselineMaturitySnapshot maturity =
                new BaselineLearningService.BaselineMaturitySnapshot(
                true,
                true,
                true,
                true,
                true,
                List.of("ACCESS_HOURS", "OPERATING_SYSTEMS"));
        when(baselineLearningService.buildPromptBaselineEvidenceSnapshot("user-123", event))
                .thenReturn(new BaselineLearningService.PromptBaselineEvidence(
                        maturity, null, null, null, null));
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
    @DisplayName("enrichBehaviorAnalysisWithBaselineSupport should not present a baseline browser as the session's previous device")
    void enrichBehaviorAnalysisWithBaselineSupport_baselineBrowserIsNotASessionDeviceChange() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-session-device")
                .userId("user-123")
                .metadata(new LinkedHashMap<>())
                .build();
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        BaselineVector baseline = BaselineVector.builder()
                .userId("user-123")
                .normalUserAgents(new String[]{"Edge/140"})
                .updateCount(25L)
                .build();
        BaselineLearningService.BaselineMaturitySnapshot maturity =
                new BaselineLearningService.BaselineMaturitySnapshot(
                true,
                true,
                true,
                true,
                true,
                List.of("ACCESS_HOURS", "OPERATING_SYSTEMS"));
        when(baselineLearningService.buildPromptBaselineEvidenceSnapshot("user-123", event))
                .thenReturn(new BaselineLearningService.PromptBaselineEvidence(maturity, baseline, null, null, null));

        strategy.enrichBehaviorAnalysisWithBaselineSupportForTest(behaviorAnalysis, event,
                Mockito.mock(SaasBaselineSeedService.class));

        assertThat(behaviorAnalysis.getBaselineUserAgents()).containsExactly("Edge/140");
        assertThat(behaviorAnalysis.getPreviousUserAgentBrowser())
                .as("a browser of the baseline is not the previous device of this session")
                .isNull();
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

    /** W4-3: the reason codes of the model response stay on the decision. */
    @Test
    void applySecurityDecisionRuntimeTelemetry_shouldKeepTheReasonCodes() {
        SecurityDecision decision = SecurityDecision.builder().action(ZeroTrustAction.CHALLENGE).build();
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setReasonCodes(List.of(new SecurityDecisionOutputContract.Citation("DEVIATION_TIME", "F1")));

        strategy.applySecurityDecisionRuntimeTelemetryForTest(decision, response);

        assertThat(decision.getReasonCodes()).containsExactly(new SecurityDecisionOutputContract.Citation("DEVIATION_TIME", "F1"));
    }

    /** W4-4: in observe mode a decision weaker than a minimum-action rule is recorded and kept as it is. */
    @Test
    void applyMinimumActionRules_recordsAWeakerDecisionAndKeepsIt() {
        CanonicalSecurityContext canonical = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder().resourceClass("SENSITIVE").actionFamily("READ").build())
                .decisionFacts(new DecisionFacts(List.of(), List.of(),
                        new PolicySatisfaction(false, null, List.of(), "no approval", List.of()), List.of()))
                .build();
        SecurityEvent allowEvent = SecurityEvent.builder()
                .metadata(new LinkedHashMap<>(Map.of("sealedEvidence.canonicalContext", canonical))).build();
        SecurityEvent challengeEvent = SecurityEvent.builder()
                .metadata(new LinkedHashMap<>(Map.of("sealedEvidence.canonicalContext", canonical))).build();
        SecurityDecision allow = SecurityDecision.builder().action(ZeroTrustAction.ALLOW).build();
        SecurityDecision challenge = SecurityDecision.builder().action(ZeroTrustAction.CHALLENGE).build();

        strategy.applyMinimumActionRulesForTest(allow, allowEvent);
        strategy.applyMinimumActionRulesForTest(challenge, challengeEvent);

        assertThat(allow.getAction()).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(allowEvent.getMetadata()).containsEntry("minimumActionMode", "OBSERVE")
                .containsEntry("minimumActionFindings", List.of(Map.of("rule", "P3_POLICY_NOT_SATISFIED",
                        "code", "MIN_P3_POLICY_NOT_SATISFIED", "requiredAction", "CHALLENGE", "dimensions", List.of(),
                        "decidedAction", "ALLOW", "violated", true)));
        assertThat(challengeEvent.getMetadata()).containsEntry("minimumActionFindings", List.of(Map.of(
                "rule", "P3_POLICY_NOT_SATISFIED", "code", "MIN_P3_POLICY_NOT_SATISFIED", "requiredAction", "CHALLENGE",
                "dimensions", List.of(), "decidedAction", "CHALLENGE", "violated", false)));
    }

    @Test
    @DisplayName("successful LLM telemetry should preserve the raw model reasoning")
    void applySecurityDecisionRuntimeTelemetry_shouldPreserveRawModelReasoning() {
        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.CHALLENGE)
                .reasoning("Raw model explanation.")
                .build();
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setFieldProvenance(Map.of("reasoning", "MODEL"));
        response.withMetadata("llmDecisionPresent", true);

        strategy.applySecurityDecisionRuntimeTelemetryForTest(decision, response);

        assertThat(decision.getLlmDecisionPresent()).isTrue();
        assertThat(decision.getTechnicalFallbackApplied()).isFalse();
        assertThat(decision.getLlmReasoning()).isEqualTo("Raw model explanation.");
    }

    @Test
    @DisplayName("same-resource authorized RAG should produce the canonical ALLOW explanation")
    void applyCanonicalDecisionReasoning_shouldUseSameResourceAllowExplanation() {
        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .reasoning("MFA verified in historical signals.")
                .llmDecisionPresent(true)
                .fieldProvenance(Map.of("reasoning", "MODEL"))
                .build();
        SecurityEvent event = SecurityEvent.builder()
                .metadata(exportMetadata("GB-500", Map.of(
                        "ragProjectedToFinalPrompt", true,
                        "personalBaselineEstablished", true)))
                .build();
        Document document = exportRecord("GB-500");

        strategy.applyCanonicalDecisionReasoningForTest(decision, event, List.of(document));

        assertThat(decision.getReasoning())
                .isEqualTo("Authorization allows access, the personal baseline is established, "
                        + "and authorized RAG is relevant to the same resource.");
        assertThat(decision.getLlmReasoning()).isEqualTo("MFA verified in historical signals.");
        assertThat(decision.getFieldProvenance()).containsEntry("reasoning", "PLATFORM_CANONICAL");
    }

    @Test
    @DisplayName("same-resource authorized RAG must not invent an absent baseline")
    void applyCanonicalDecisionReasoning_shouldNotInventAbsentBaseline() {
        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .reasoning("Model explanation.")
                .llmDecisionPresent(true)
                .fieldProvenance(Map.of("reasoning", "MODEL"))
                .build();
        SecurityEvent event = SecurityEvent.builder()
                .metadata(exportMetadata("GB-500", Map.of(
                        "ragProjectedToFinalPrompt", true,
                        "personalBaselineEstablished", false)))
                .build();
        Document document = exportRecord("GB-500");

        strategy.applyCanonicalDecisionReasoningForTest(decision, event, List.of(document));

        assertThat(decision.getReasoning())
                .isEqualTo("Authorization allows access, and authorized RAG is relevant to the same resource.");
        assertThat(decision.getReasoning()).doesNotContain("baseline");
    }

    @Test
    @DisplayName("ALLOW without same-resource RAG states the baseline from the canonical facts, not the model")
    void applyCanonicalDecisionReasoning_shouldStateLimitedBaselineWithoutRag() {
        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .reasoning("Authorization allows access, the personal baseline is established, "
                        + "and no concrete risk or verification requirement is present.")
                .llmDecisionPresent(true)
                .fieldProvenance(Map.of("reasoning", "MODEL"))
                .build();
        SecurityEvent event = SecurityEvent.builder()
                .metadata(new LinkedHashMap<>(Map.of("personalBaselineEstablished", false)))
                .build();

        strategy.applyCanonicalDecisionReasoningForTest(decision, event, List.of());

        assertThat(decision.getReasoning()).isEqualTo("Authorization allows access with a limited baseline, "
                + "and no concrete risk or verification requirement is present.");
        assertThat(decision.getLlmReasoning()).contains("the personal baseline is established");
        assertThat(decision.getFieldProvenance()).containsEntry("reasoning", "PLATFORM_CANONICAL");
    }

    @Test
    @DisplayName("ALLOW without same-resource RAG keeps a model explanation that matches the facts")
    void applyCanonicalDecisionReasoning_shouldKeepModelExplanationWithoutRag() {
        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .reasoning("Authorization allows access, the personal baseline is established, "
                        + "and no concrete risk or verification requirement is present.")
                .llmDecisionPresent(true)
                .fieldProvenance(Map.of("reasoning", "MODEL"))
                .build();
        SecurityEvent event = SecurityEvent.builder()
                .metadata(new LinkedHashMap<>(Map.of("personalBaselineEstablished", true)))
                .build();

        strategy.applyCanonicalDecisionReasoningForTest(decision, event, List.of());

        assertThat(decision.getReasoning()).contains("the personal baseline is established");
        assertThat(decision.getFieldProvenance()).containsEntry("reasoning", "MODEL");
    }

    @Test
    @DisplayName("records of the same method on another project are not same-resource RAG (W2-8)")
    void applyCanonicalDecisionReasoning_anotherProjectIsNotTheSameResource() {
        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .reasoning("Authorization allows access, the personal baseline is established, "
                        + "and authorized RAG is relevant to the same resource.")
                .llmDecisionPresent(true)
                .fieldProvenance(Map.of("reasoning", "MODEL"))
                .build();
        SecurityEvent event = SecurityEvent.builder()
                .metadata(exportMetadata("GB-500", Map.of(
                        "ragProjectedToFinalPrompt", true,
                        "personalBaselineEstablished", true)))
                .build();

        strategy.applyCanonicalDecisionReasoningForTest(decision, event, List.of(exportRecord("PLM-OPS")));

        // The model's same-resource claim is not true of these records; the rule-2 sentence replaces it.
        assertThat(decision.getReasoning()).isEqualTo("Authorization allows access, the personal baseline is established, "
                + "and no concrete risk or verification requirement is present.");
        assertThat(decision.getLlmReasoning()).contains("relevant to the same resource");
        assertThat(decision.getFieldProvenance()).containsEntry("reasoning", "PLATFORM_CANONICAL");
    }

    @Test
    @DisplayName("a same-resource claim without such records and without a baseline gets the limited sentence (W2-8)")
    void applyCanonicalDecisionReasoning_aSameResourceClaimWithoutRecordsOrBaseline() {
        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .reasoning("Authorization allows access, and authorized RAG is relevant to the same resource.")
                .llmDecisionPresent(true)
                .fieldProvenance(Map.of("reasoning", "MODEL"))
                .build();
        SecurityEvent event = SecurityEvent.builder()
                .metadata(exportMetadata("GB-500", Map.of(
                        "ragProjectedToFinalPrompt", true,
                        "personalBaselineEstablished", false)))
                .build();

        strategy.applyCanonicalDecisionReasoningForTest(decision, event,
                List.of(exportRecord("GB-500"), exportRecord("PLM-OPS")));

        assertThat(decision.getReasoning()).isEqualTo("Authorization allows access with a limited baseline, "
                + "and no concrete risk or verification requirement is present.");
    }

    @Test
    @DisplayName("past records leave out the current session and records held back from promotion (W2-8)")
    void searchRelatedContextBase_leavesOutTheCurrentSessionAndHeldRecords() {
        SimpleVectorStore store = SimpleVectorStore.builder(new ConstantEmbeddingModel()).build();
        Document otherSession = behaviorRecord("other-session", Map.of("sessionId", "session-1"));
        Document noSession = behaviorRecord("no-session", Map.of());
        store.add(List.of(
                behaviorRecord("this-session", Map.of("sessionId", "session-7")),
                otherSession,
                noSession,
                behaviorRecord("held", Map.of("sessionId", "session-2", "learningState", "HELD"))));
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-session-7")
                .userId("adm-a")
                .sessionId("session-7")
                .metadata(new LinkedHashMap<>(Map.of(
                        "organizationId", "demo-org",
                        "resourceId", "ops#exportDocuments",
                        "httpMethod", "POST")))
                .build();
        when(eventEnricher.getTargetResource(event)).thenReturn(Optional.of("/api/projects/GB-500/exports"));
        // The store evaluates the very filter the strategy built.
        when(unifiedVectorService.searchSimilar(any(SearchRequest.class)))
                .thenAnswer(invocation -> store.similaritySearch((SearchRequest) invocation.getArgument(0)));
        when(promptContextAuthorizationService.authorize(
                any(SecurityEvent.class),
                any(),
                ArgumentMatchers.<List<Document>>any()))
                .thenAnswer(invocation -> {
                    List<Document> documents = invocation.getArgument(2);
                    return new AuthorizedPromptContext(
                            documents, documents.size(), documents.size(), 0, "security_investigation", List.of());
                });

        List<Document> result = strategy.callSearchRelatedContextBase(event, 5, 0.0d);

        assertThat(result).extracting(Document::getId).containsExactlyInAnyOrder("other-session", "no-session");
        ArgumentCaptor<SearchRequest> searches = ArgumentCaptor.forClass(SearchRequest.class);
        verify(unifiedVectorService, Mockito.atLeastOnce()).searchSimilar(searches.capture());
        // The personal searches leave out the session; the organization's supporting search already leaves out the user.
        assertThat(searches.getAllValues())
                .filteredOn(search -> String.valueOf(search.getFilterExpression()).contains("adm-a"))
                .isNotEmpty()
                .allSatisfy(search -> assertThat(String.valueOf(search.getFilterExpression()))
                        // NIN keeps a record without a session; a not-equal test would drop it in pgvector.
                        .contains("type=NIN, left=Key[key=sessionId], right=Value[value=[session-7]]"));
        assertThat(searches.getAllValues()).allSatisfy(search -> assertThat(String.valueOf(search.getFilterExpression()))
                .contains("learningState", "HELD"));
    }

    @Test
    @DisplayName("past records written under the ids the session had before a step-up check are its own (P2 correction 5)")
    void searchRelatedContextBase_leavesOutTheSessionsRecordsUnderItsEarlierIds() {
        SimpleVectorStore store = SimpleVectorStore.builder(new ConstantEmbeddingModel()).build();
        store.add(List.of(
                behaviorRecord("before-step-up", Map.of("sessionId", "session-6")),
                behaviorRecord("this-session", Map.of("sessionId", "session-7")),
                behaviorRecord("other-session", Map.of("sessionId", "session-1"))));
        strategy.previousIds.put("session-7", List.of("session-6"));
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-session-7-after-step-up")
                .userId("adm-a")
                .sessionId("session-7")
                .metadata(new LinkedHashMap<>(Map.of(
                        "organizationId", "demo-org",
                        "resourceId", "ops#exportDocuments",
                        "httpMethod", "POST")))
                .build();
        when(eventEnricher.getTargetResource(event)).thenReturn(Optional.of("/api/projects/GB-500/exports"));
        when(unifiedVectorService.searchSimilar(any(SearchRequest.class)))
                .thenAnswer(invocation -> store.similaritySearch((SearchRequest) invocation.getArgument(0)));
        when(promptContextAuthorizationService.authorize(
                any(SecurityEvent.class),
                any(),
                ArgumentMatchers.<List<Document>>any()))
                .thenAnswer(invocation -> {
                    List<Document> documents = invocation.getArgument(2);
                    return new AuthorizedPromptContext(
                            documents, documents.size(), documents.size(), 0, "security_investigation", List.of());
                });

        List<Document> result = strategy.callSearchRelatedContextBase(event, 5, 0.0d);

        assertThat(result).extracting(Document::getId).containsExactly("other-session");
        ArgumentCaptor<SearchRequest> searches = ArgumentCaptor.forClass(SearchRequest.class);
        verify(unifiedVectorService, Mockito.atLeastOnce()).searchSimilar(searches.capture());
        assertThat(searches.getAllValues())
                .filteredOn(search -> String.valueOf(search.getFilterExpression()).contains("adm-a"))
                .isNotEmpty()
                .allSatisfy(search -> assertThat(String.valueOf(search.getFilterExpression()))
                        .contains("type=NIN, left=Key[key=sessionId], right=Value[value=[session-7, session-6]]"));
    }

    @Test
    @DisplayName("a request without a session keeps every learned record of the user (W2-8)")
    void searchRelatedContextBase_withoutASessionLeavesOutOnlyHeldRecords() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-no-session")
                .userId("adm-a")
                .metadata(new LinkedHashMap<>(Map.of("organizationId", "demo-org", "httpMethod", "POST")))
                .build();
        when(eventEnricher.getTargetResource(event)).thenReturn(Optional.of("/api/projects/GB-500/exports"));
        when(unifiedVectorService.searchSimilar(any(SearchRequest.class))).thenReturn(List.of());

        strategy.callSearchRelatedContextBase(event, 5, 0.0d);

        ArgumentCaptor<SearchRequest> searches = ArgumentCaptor.forClass(SearchRequest.class);
        verify(unifiedVectorService, Mockito.atLeastOnce()).searchSimilar(searches.capture());
        assertThat(searches.getAllValues()).allSatisfy(search -> assertThat(String.valueOf(search.getFilterExpression()))
                .doesNotContain("sessionId")
                .contains("learningState", "HELD"));
    }

    private static Map<String, Object> exportMetadata(String project, Map<String, Object> extra) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("resourceId", "ops#exportDocuments");
        metadata.put("requestPath", "/api/projects/" + project + "/exports");
        metadata.put("protectableResourceUrl", "/api/projects/{projectKey}/exports");
        metadata.put("httpMethod", "POST");
        metadata.putAll(extra);
        return metadata;
    }

    private static Document exportRecord(String project) {
        return new Document("historical evidence", Map.of(
                "resourceId", "ops#exportDocuments",
                "requestPath", "/api/projects/" + project + "/exports",
                "pathFamily", "/api/projects/{projectKey}/exports",
                "httpMethod", "POST"));
    }

    private static Document behaviorRecord(String id, Map<String, Object> extra) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("documentType", "behavior");
        metadata.put("eventId", id);
        metadata.put("userId", "adm-a");
        metadata.put("retrievalPurpose", "security_investigation");
        metadata.put("resourceId", "ops#exportDocuments");
        metadata.putAll(extra);
        return Document.builder().id(id).text("User accessed /api/projects/PLM-OPS/exports via POST").metadata(metadata)
                .build();
    }

    /** Every text embeds to the same vector, so the store's filter alone decides what a search returns. */
    private static final class ConstantEmbeddingModel implements EmbeddingModel {

        @Override
        public EmbeddingResponse call(EmbeddingRequest request) {
            List<Embedding> embeddings = new ArrayList<>();
            for (int index = 0; index < request.getInstructions().size(); index++) {
                embeddings.add(new Embedding(new float[] {1f, 0f}, index));
            }
            return new EmbeddingResponse(embeddings);
        }

        @Override
        public float[] embed(Document document) {
            return new float[] {1f, 0f};
        }

        @Override
        public int dimensions() {
            return 2;
        }
    }

    // -- Concrete test implementation of the abstract class --

    private static final String EXPORTS = "/api/projects/{projectKey}/exports";
    private static final String GB500 = "/api/projects/GB-500/exports";

    /** W3-18: a v20 request reads its past records by the exact lookup of its action family, without a similarity search. */
    @Test
    void aV20RequestReadsItsPastRecordsByTheExactLookupOfItsActionFamily() {
        SecurityEvent event = exportEvent("event-w318-exact", true);
        when(promptTemplate.promptBundle(event)).thenReturn(SecurityDecisionPromptBundles.V20);
        Document sameTarget = new Document("00000000-0000-0000-0000-000000000002", "record same target",
                Map.of("eventId", "e2", "requestPath", GB500, "pathFamily", EXPORTS, "actionFamily", "EXPORT"));
        Document otherTarget = new Document("00000000-0000-0000-0000-000000000003", "record other target",
                Map.of("eventId", "e3", "requestPath", "/api/projects/PLM-OPS/exports", "pathFamily", EXPORTS,
                        "actionFamily", "EXPORT"));
        RecordingPastRecordQuery query = new RecordingPastRecordQuery(List.of(
                new PastRecordGroup(EXPORTS, GB500, "POST", 2, LocalDateTime.of(2026, 10, 12, 11, 0)),
                new PastRecordGroup(EXPORTS, "/api/projects/PLM-OPS/exports", "POST", 1, LocalDateTime.of(2026, 10, 11, 9, 0))),
                List.of(sameTarget, otherTarget));
        when(unifiedVectorService.pastRecordQuery()).thenReturn(query);
        authorizeEveryDocument();

        List<Document> result = strategy.callSearchRelatedContextBase(event, 5, 0.5d);

        assertThat(result).containsExactly(sameTarget, otherTarget);
        verify(unifiedVectorService, never()).searchSimilar(any(SearchRequest.class));
        assertThat(query.scope).isEqualTo(new PastRecordScope("alice", "security_investigation", "EXPORT", List.of("session-now")));
        assertThat(query.firstPaths).containsExactly(GB500);
        assertThat(query.limit).isEqualTo(5);
        assertThat(event.getMetadata())
                .containsEntry("ragRetrievalState", "AVAILABLE")
                .containsEntry("ragSearchMode", "EXACT_PAST_RECORD_LOOKUP")
                .containsEntry("relatedDocumentCount", 2);
        assertThat(PastRecordCounts.fromMetadata(event.getMetadata().get("ragPastRecordCounts"))).isEqualTo(
                new PastRecordCounts("EXPORT", "POST " + EXPORTS, 2, LocalDateTime.of(2026, 10, 12, 11, 0), 1,
                        LocalDateTime.of(2026, 10, 11, 9, 0), 0, 3));
    }

    /**
     * W3-19 (one fact, one source): the candidates of an exact lookup are the records it counted, not the ones it read
     * up to its limit, so the state line and the counts state one number of past records.
     */
    @Test
    void theCandidatesOfAnExactLookupAreTheRecordsItCountedNotTheOnesItRead() {
        SecurityEvent event = exportEvent("event-w319-candidates", true);
        when(promptTemplate.promptBundle(event)).thenReturn(SecurityDecisionPromptBundles.V20);
        Document sameTarget = new Document("00000000-0000-0000-0000-000000000012", "record same target",
                Map.of("eventId", "e12", "requestPath", GB500, "pathFamily", EXPORTS, "actionFamily", "EXPORT"));
        Document otherTarget = new Document("00000000-0000-0000-0000-000000000013", "record other target",
                Map.of("eventId", "e13", "requestPath", "/api/projects/PLM-OPS/exports", "pathFamily", EXPORTS,
                        "actionFamily", "EXPORT"));
        RecordingPastRecordQuery query = new RecordingPastRecordQuery(List.of(
                new PastRecordGroup(EXPORTS, GB500, "POST", 1, LocalDateTime.of(2026, 10, 12, 11, 0)),
                new PastRecordGroup(EXPORTS, "/api/projects/PLM-OPS/exports", "POST", 14, LocalDateTime.of(2026, 10, 11, 9, 0))),
                List.of(sameTarget, otherTarget));
        when(unifiedVectorService.pastRecordQuery()).thenReturn(query);
        authorizeEveryDocument();

        strategy.callSearchRelatedContextBase(event, 2, 0.5d);

        assertThat(event.getMetadata())
                .containsEntry("relatedDocumentCount", 2)
                .containsEntry("ragCandidateDocumentCount", 15);
    }

    @Test
    void aV20RequestWithoutAnExactLookupSaysThePastRecordsWereNotRetrieved() {
        SecurityEvent event = exportEvent("event-w318-unavailable", true);
        when(promptTemplate.promptBundle(event)).thenReturn(SecurityDecisionPromptBundles.V20);
        when(unifiedVectorService.pastRecordQuery()).thenReturn(PastRecordQuery.unavailable());

        assertThat(strategy.callSearchRelatedContextBase(event, 5, 0.5d)).isEmpty();
        verify(unifiedVectorService, never()).searchSimilar(any(SearchRequest.class));
        assertThat(event.getMetadata())
                .containsEntry("ragRetrievalState", "UNAVAILABLE")
                .doesNotContainKey("ragPastRecordCounts");
    }

    @Test
    void aV20RequestWithoutAnActionFamilyIsNotLookedUp() {
        SecurityEvent event = exportEvent("event-w318-no-action", false);
        when(promptTemplate.promptBundle(event)).thenReturn(SecurityDecisionPromptBundles.V20);
        RecordingPastRecordQuery query = new RecordingPastRecordQuery(List.of(), List.of());
        when(unifiedVectorService.pastRecordQuery()).thenReturn(query);

        assertThat(strategy.callSearchRelatedContextBase(event, 5, 0.5d)).isEmpty();
        assertThat(query.scope).isNull();
        verify(unifiedVectorService, never()).searchSimilar(any(SearchRequest.class));
        assertThat(event.getMetadata())
                .containsEntry("ragRetrievalState", "NOT_REQUESTED")
                .containsEntry("ragAbsenceReason", "ACTION_FAMILY_UNKNOWN");
    }

    /** The v19 bundle stays the comparison baseline: it searches its past records as before. */
    @Test
    void aV19RequestSearchesItsPastRecordsAsBefore() {
        SecurityEvent event = exportEvent("event-w318-v19", true);
        when(promptTemplate.promptBundle(event)).thenReturn(SecurityDecisionPromptBundles.DEFAULT);
        when(unifiedVectorService.searchSimilar(any(SearchRequest.class))).thenReturn(List.of());

        strategy.callSearchRelatedContextBase(event, 5, 0.5d);

        verify(unifiedVectorService, atLeastOnce()).searchSimilar(any(SearchRequest.class));
        verify(unifiedVectorService, never()).pastRecordQuery();
    }

    private static SecurityEvent exportEvent(String eventId, boolean withAction) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("requestPath", withAction ? GB500 : "/x/y");
        if (withAction) {
            metadata.put("resourceUrlTemplate", EXPORTS);
            metadata.put("httpMethod", "POST");
            metadata.put("actionFamily", "EXPORT");
            metadata.put("resourceId", "ops#exportDocuments");
        }
        return SecurityEvent.builder()
                .eventId(eventId)
                .userId("alice")
                .sessionId("session-now")
                .metadata(metadata)
                .build();
    }

    private void authorizeEveryDocument() {
        when(promptContextAuthorizationService.authorize(
                any(SecurityEvent.class),
                any(),
                ArgumentMatchers.<List<Document>>any()))
                .thenAnswer(invocation -> {
                    List<Document> documents = invocation.getArgument(2);
                    return new AuthorizedPromptContext(documents, documents.size(), documents.size(), 0,
                            "security_investigation", List.of());
                });
    }

    /** A past record query that keeps what it was asked. */
    private static final class RecordingPastRecordQuery implements PastRecordQuery {

        private final List<PastRecordGroup> groups;
        private final List<Document> records;
        private PastRecordScope scope;
        private List<String> firstPaths;
        private int limit;

        private RecordingPastRecordQuery(List<PastRecordGroup> groups, List<Document> records) {
            this.groups = groups;
            this.records = records;
        }

        @Override
        public boolean available() {
            return true;
        }

        @Override
        public List<PastRecordGroup> groups(PastRecordScope scope) {
            this.scope = scope;
            return groups;
        }

        @Override
        public List<Document> records(PastRecordScope scope, List<String> firstPaths, int limit) {
            this.firstPaths = firstPaths;
            this.limit = limit;
            return records;
        }
    }

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

        /** The ids a session had before its id was replaced, as a context store would give them. */
        final Map<String, List<String>> previousIds = new HashMap<>();

        @Override
        protected List<String> previousSessionIds(String sessionId) {
            return previousIds.getOrDefault(sessionId, List.of());
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

        void applyMinimumActionRulesForTest(SecurityDecision decision, SecurityEvent event) {
            applyMinimumActionRules(decision, event);
        }

        void applySecurityDecisionRuntimeTelemetryForTest(
                SecurityDecision decision,
                SecurityDecisionResponse response) {
            applySecurityDecisionRuntimeTelemetry(decision, response);
        }

        void applyCanonicalDecisionReasoningForTest(
                SecurityDecision decision,
                SecurityEvent event,
                List<Document> relatedDocuments) {
            applyCanonicalDecisionReasoning(decision, event, relatedDocuments);
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

    @Test
    @DisplayName("searchRelatedContextBase asks a margin more and keeps the same past records whatever order the store returns (W3-3)")
    void searchRelatedContextBase_ranksPastRecordsByFixedKeysWithAMargin() {
        List<Document> stored = new ArrayList<>();
        for (int index = 1; index <= 6; index++) {
            stored.add(Document.builder()
                    .id("doc-" + index)
                    .text("User accessed record " + index)
                    .metadata(Map.of("userId", "persona_fin_lead", "documentType", "behavior",
                            "eventId", "event-" + index, "timestamp", "2026-09-24T09:00"))
                    .score(0.80)
                    .build());
        }
        List<Document> reversed = new ArrayList<>(stored);
        Collections.reverse(reversed);
        AtomicBoolean firstRun = new AtomicBoolean(true);
        when(unifiedVectorService.searchSimilar(any(SearchRequest.class)))
                .thenAnswer(invocation -> firstRun.get() ? stored : reversed);
        when(baselineLearningService.describeBaselineMaturity(any(), any()))
                .thenReturn(new BaselineLearningService.BaselineMaturitySnapshot(
                        true, true, true, true, true, List.of("ACCESS_HOURS")));
        when(promptContextAuthorizationService.authorize(
                any(SecurityEvent.class),
                any(),
                ArgumentMatchers.<List<Document>>any()))
                .thenAnswer(invocation -> {
                    List<Document> documents = invocation.getArgument(2);
                    return new AuthorizedPromptContext(documents, documents.size(), documents.size(), 0,
                            "security_investigation", List.of());
                });

        List<Document> first = strategy.callSearchRelatedContextBase(pastRecordEvent("event-margin-1"), 3, 0.7d);
        firstRun.set(false);
        List<Document> second = strategy.callSearchRelatedContextBase(pastRecordEvent("event-margin-2"), 3, 0.7d);

        assertThat(first).extracting(Document::getId).containsExactly("doc-1", "doc-2", "doc-3");
        assertThat(second).extracting(Document::getId).containsExactly("doc-1", "doc-2", "doc-3");
        ArgumentCaptor<SearchRequest> searchRequestCaptor = ArgumentCaptor.forClass(SearchRequest.class);
        verify(unifiedVectorService, Mockito.atLeastOnce()).searchSimilar(searchRequestCaptor.capture());
        assertThat(searchRequestCaptor.getAllValues()).extracting(SearchRequest::getTopK).contains(6).doesNotContain(3);
    }

    @Test
    @DisplayName("searchRelatedContextBase keeps one copy of a record that more than one search found, whatever its document ID (W3-3)")
    void searchRelatedContextBase_keepsOneCopyOfARecordFoundByMoreThanOneSearch() {
        AtomicInteger copies = new AtomicInteger();
        when(unifiedVectorService.searchSimilar(any(SearchRequest.class)))
                .thenAnswer(invocation -> List.of(Document.builder()
                        .id("copy-" + copies.incrementAndGet())
                        .text("User exported project GB-500")
                        .metadata(Map.of("userId", "persona_fin_lead", "documentType", "behavior",
                                "eventId", "event-shared", "timestamp", "2026-09-24T09:00"))
                        .score(0.80)
                        .build()));
        when(baselineLearningService.describeBaselineMaturity(any(), any()))
                .thenReturn(new BaselineLearningService.BaselineMaturitySnapshot(
                        true, true, true, true, true, List.of("ACCESS_HOURS")));
        when(promptContextAuthorizationService.authorize(
                any(SecurityEvent.class),
                any(),
                ArgumentMatchers.<List<Document>>any()))
                .thenAnswer(invocation -> {
                    List<Document> documents = invocation.getArgument(2);
                    return new AuthorizedPromptContext(documents, documents.size(), documents.size(), 0,
                            "security_investigation", List.of());
                });

        List<Document> result = strategy.callSearchRelatedContextBase(pastRecordEvent("event-copies"), 3, 0.7d);

        assertThat(copies.get()).isGreaterThan(1);
        assertThat(result).hasSize(1);
        assertThat(result.get(0).getMetadata()).containsEntry("eventId", "event-shared");
    }

    /**
     * N-MISS-1 (D8): a search after one that timed out on the same event (Layer2 after Layer1) writes what it found and
     * keeps the earlier timeout as a fact of its own.
     */
    @Test
    void aSearchAfterATimedOutSearchWritesWhatItFoundAndKeepsTheTimeoutApart() {
        SecurityEvent event = pastRecordEvent("event-after-timeout");
        event.getMetadata().put("ragTimedOut", true);
        event.getMetadata().put("ragRetrievalState", "TIMEOUT");
        event.getMetadata().put("ragAbsenceReason", "TIMEOUT");
        event.getMetadata().put("relatedDocumentCount", 0);
        when(unifiedVectorService.searchSimilar(any(SearchRequest.class))).thenReturn(List.of(pastRecord("found-1")));
        authorizeEveryRecord();

        List<Document> result = strategy.callSearchRelatedContextBase(event, 3, 0.7d);

        assertThat(result).hasSize(1);
        assertThat(event.getMetadata())
                .containsEntry("ragRetrievalState", "AVAILABLE")
                .containsEntry("ragTimedOut", false)
                .containsEntry("relatedDocumentCount", 1)
                .containsEntry("ragCandidateDocumentCount", 1)
                .containsEntry("ragEarlierRetrievalState", "TIMEOUT")
                .doesNotContainKey("ragAbsenceReason");
    }

    /** N-MISS-1 (D8): a search whose own wait ran out while it ran does not write its late records over the timeout. */
    @Test
    void aSearchThatTimedOutWhileRunningDoesNotWriteItsLateRecords() {
        SecurityEvent event = pastRecordEvent("event-late");
        event.getMetadata().put("ragTimedOut", false);
        event.getMetadata().put("ragRetrievalState", "NOT_REQUESTED");
        when(unifiedVectorService.searchSimilar(any(SearchRequest.class))).thenAnswer(invocation -> {
            // The waiting layer gives up while the search still runs on the event it writes.
            event.getMetadata().put("ragTimedOut", true);
            event.getMetadata().put("ragRetrievalState", "TIMEOUT");
            return List.of(pastRecord("late-1"));
        });
        authorizeEveryRecord();

        strategy.callSearchRelatedContextBase(event, 3, 0.7d);

        assertThat(event.getMetadata())
                .containsEntry("ragRetrievalState", "TIMEOUT")
                .containsEntry("ragTimedOut", true)
                .doesNotContainKey("ragEarlierRetrievalState");
    }

    /** N-MISS-1 (D8): a search that a newer one on the same event overtook does not write over what the newer found. */
    @Test
    void aSearchThatANewerOneOvertookDoesNotWriteOverIt() {
        SecurityEvent event = pastRecordEvent("event-overtaken");
        AtomicBoolean newerStarted = new AtomicBoolean();
        AtomicBoolean newerRunning = new AtomicBoolean();
        when(unifiedVectorService.searchSimilar(any(SearchRequest.class))).thenAnswer(invocation -> {
            if (newerRunning.get()) {
                return List.of();
            }
            if (newerStarted.compareAndSet(false, true)) {
                newerRunning.set(true);
                strategy.callSearchRelatedContextBase(event, 3, 0.7d);
                newerRunning.set(false);
            }
            return List.of(pastRecord("older-1"));
        });
        authorizeEveryRecord();

        List<Document> older = strategy.callSearchRelatedContextBase(event, 3, 0.7d);

        assertThat(older).isNotEmpty();
        assertThat(event.getMetadata())
                .containsEntry("ragRetrievalState", "ZERO_RESULTS")
                .containsEntry("relatedDocumentCount", 0);
    }

    private static Document pastRecord(String eventId) {
        return Document.builder()
                .id(eventId)
                .text("User exported project GB-500")
                .metadata(Map.of("userId", "persona_fin_lead", "documentType", "behavior",
                        "eventId", eventId, "timestamp", "2026-09-24T09:00"))
                .score(0.80)
                .build();
    }

    private void authorizeEveryRecord() {
        when(promptContextAuthorizationService.authorize(
                any(SecurityEvent.class),
                any(),
                ArgumentMatchers.<List<Document>>any()))
                .thenAnswer(invocation -> {
                    List<Document> documents = invocation.getArgument(2);
                    return new AuthorizedPromptContext(documents, documents.size(), documents.size(), 0,
                            "security_investigation", List.of());
                });
    }

    private SecurityEvent pastRecordEvent(String eventId) {
        SecurityEvent event = SecurityEvent.builder()
                .eventId(eventId)
                .userId("persona_fin_lead")
                .sourceIp("10.10.0.20")
                .metadata(new LinkedHashMap<>(Map.of(
                        "organizationId", "demo-org",
                        "resourceId", "resource-001",
                        "httpMethod", "GET")))
                .build();
        when(eventEnricher.getTargetResource(event)).thenReturn(Optional.of("/api/documents/resource-001"));
        return event;
    }
}
