package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityResponse;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.saas.PromptContextAuditForwardingService;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
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
    @DisplayName("searchRelatedContextBase는 behavior memory와 동일 retrievalPurpose만 조회하고 authorized topK가 찰 때까지 검색 창을 넓혀야 한다")
    void searchRelatedContextBase_shouldFilterToBehaviorAndPurposeAndExpandSearchWindow() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-001")
                .userId("user-1")
                .sourceIp("192.168.1.100")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .metadata(new LinkedHashMap<>(Map.of("requestPath", "/admin/api/security-test/sensitive/resource-001")))
                .build();

        when(eventEnricher.getTargetResource(event))
                .thenReturn(Optional.of("/admin/api/security-test/sensitive/resource-001"));

        List<Document> firstSearchDocuments = List.of(
                new Document("doc-1", Map.of("userId", "user-1", "documentType", "behavior", "retrievalPurpose", "security_investigation")),
                new Document("doc-2", Map.of("userId", "user-1", "documentType", "behavior", "retrievalPurpose", "security_investigation")),
                new Document("doc-3", Map.of("userId", "user-1", "documentType", "behavior", "retrievalPurpose", "security_investigation")),
                new Document("doc-4", Map.of("userId", "user-1", "documentType", "behavior", "retrievalPurpose", "security_investigation")),
                new Document("doc-5", Map.of("userId", "user-1", "documentType", "behavior", "retrievalPurpose", "security_investigation")),
                new Document("doc-6", Map.of("userId", "user-1", "documentType", "behavior", "retrievalPurpose", "security_investigation")));
        List<Document> secondSearchDocuments = List.of(
                new Document("doc-1", Map.of("userId", "user-1", "documentType", "behavior", "retrievalPurpose", "security_investigation")),
                new Document("doc-2", Map.of("userId", "user-1", "documentType", "behavior", "retrievalPurpose", "security_investigation")),
                new Document("doc-3", Map.of("userId", "user-1", "documentType", "behavior", "retrievalPurpose", "security_investigation")),
                new Document("doc-4", Map.of("userId", "user-1", "documentType", "behavior", "retrievalPurpose", "security_investigation")),
                new Document("doc-5", Map.of("userId", "user-1", "documentType", "behavior", "retrievalPurpose", "security_investigation")),
                new Document("doc-6", Map.of("userId", "user-1", "documentType", "behavior", "retrievalPurpose", "security_investigation")),
                new Document("doc-7", Map.of("userId", "user-1", "documentType", "behavior", "retrievalPurpose", "security_investigation")));

        when(unifiedVectorService.searchSimilar(any(SearchRequest.class)))
                .thenReturn(firstSearchDocuments)
                .thenReturn(secondSearchDocuments);
        when(promptContextAuthorizationService.authorize(any(SecurityEvent.class), any(String.class), any(List.class)))
                .thenReturn(new io.contexa.contexacore.std.security.AuthorizedPromptContext(
                        List.of(firstSearchDocuments.getFirst()),
                        firstSearchDocuments.size(),
                        1,
                        firstSearchDocuments.size() - 1,
                        "security_investigation",
                        List.of("DENIED_PURPOSE")))
                .thenReturn(new io.contexa.contexacore.std.security.AuthorizedPromptContext(
                        secondSearchDocuments.subList(0, 6),
                        secondSearchDocuments.size(),
                        6,
                        secondSearchDocuments.size() - 6,
                        "security_investigation",
                        List.of("DENIED_USER_SCOPE")));

        List<Document> results = strategy.callSearchRelatedContextBase(event, 6, 0.5d);

        assertThat(results).hasSize(6);

        ArgumentCaptor<SearchRequest> searchRequestCaptor = ArgumentCaptor.forClass(SearchRequest.class);
        verify(unifiedVectorService, times(2)).searchSimilar(searchRequestCaptor.capture());
        List<SearchRequest> capturedRequests = searchRequestCaptor.getAllValues();
        assertThat(capturedRequests.get(0).getTopK()).isEqualTo(6);
        assertThat(capturedRequests.get(1).getTopK()).isEqualTo(12);
        assertThat(String.valueOf(capturedRequests.get(0).getFilterExpression()))
                .contains("documentType")
                .contains("behavior")
                .contains("userId")
                .contains("user-1")
                .contains("retrievalPurpose")
                .contains("security_investigation")
                .doesNotContain("threat");
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

        strategy.capturePromptRuntimeTelemetryForTest(event, response);

        assertThat(event.getMetadata())
                .containsEntry("existingKey", "existingValue")
                .containsEntry("promptVersion", "2026.03.27-e0.2")
                .containsEntry("promptHash", "sha256:test-prompt")
                .containsEntry("budgetProfile", "CORTEX_L2_STANDARD")
                .containsEntry("promptEvidenceCompleteness", "SUFFICIENT")
                .containsEntry("promptRuntimeTelemetryLinked", true)
                .containsEntry("promptRuntimeTelemetryLayer", "TestLayer");
        assertThat(event.getMetadata().get("promptSectionSet")).isEqualTo(List.of("CURRENT_REQUEST", "ROLE_SCOPE"));
        assertThat(event.getMetadata()).isInstanceOf(LinkedHashMap.class);
    }

    @Test
    @DisplayName("clearPromptRuntimeTelemetry should remove stale prompt runtime facts")
    void clearPromptRuntimeTelemetry_removesStaleFacts() {
        SecurityEvent event = SecurityEvent.builder()
                .metadata(new LinkedHashMap<>(java.util.Map.of(
                        "promptVersion", "stale-version",
                        "promptHash", "sha256:stale",
                        "budgetProfile", "CORTEX_L1_STANDARD",
                        "promptRuntimeTelemetryLinked", true,
                        "promptRuntimeTelemetryLayer", "Layer1",
                        "preserveKey", "preserveValue")))
                .build();

        strategy.clearPromptRuntimeTelemetryForTest(event);

        assertThat(event.getMetadata())
                .doesNotContainKeys(
                        "promptVersion",
                        "promptHash",
                        "budgetProfile",
                        "promptRuntimeTelemetryLinked",
                        "promptRuntimeTelemetryLayer")
                .containsEntry("preserveKey", "preserveValue");
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
    }
}
