package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityResponse;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.saas.PromptContextAuditForwardingService;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
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


