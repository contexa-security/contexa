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
package io.contexa.contexacore.std.pipeline.executor;

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.SecurityEvent;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.LLMOperations;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionResponseProcessor;
import io.contexa.contexacore.std.pipeline.step.ContextRetrievalStep;
import io.contexa.contexacore.std.pipeline.step.LLMExecutionStep;
import io.contexa.contexacore.std.pipeline.step.PostprocessingStep;
import io.contexa.contexacore.std.pipeline.step.PreprocessingStep;
import io.contexa.contexacore.std.pipeline.step.PromptGenerationStep;
import io.contexa.contexacore.std.pipeline.step.ResponseParsingStep;
import io.contexa.contexacore.std.pipeline.step.StructuredOutputPolicy;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;


class SecurityDecisionStructuredOutputPipelineIntegrationTest {

    @Test
    void rawGuardedPipelineShouldProduceSecurityDecisionResponseWithoutSpringEntityParsing() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = """
                {
                  "action": "ALLOW",
                  "confidence": 0.81,
                  "riskScore": 0.16,
                  "reasoning": "Verified identity and scope align with a low-risk post-auth request.",
                  "mitre": "UNKNOWN"
                }
                """;

        UniversalPipelineExecutor executor = buildExecutor(llmClient);
        SecurityDecisionResponse response = executor.execute(
                        buildRequest(),
                        PipelineConfiguration.createPipelineConfig(),
                        SecurityDecisionResponse.class)
                .block();

        assertThat(response).isNotNull();
        assertThat(response.getAction()).isEqualTo("ALLOW");
        assertThat(response.getConfidence()).isEqualTo(0.81d);
        assertThat(response.getRiskScore()).isEqualTo(0.16d);
        assertThat(response.getMetadata("entityExecutionAttempted", Boolean.class)).isFalse();
        assertThat(response.getMetadata("entityExecutionSucceeded", Boolean.class)).isFalse();
        assertThat(response.getMetadata("rawExecutionAttempted", Boolean.class)).isTrue();
        assertThat(response.getMetadata("securityDecisionParsingMode", String.class)).isEqualTo("RAW_GUARDED");
        assertThat(response.getMetadata("securityDecisionParsingFallbackApplied", Boolean.class)).isFalse();
        assertThat(llmClient.entityExecutions).isZero();
        assertThat(llmClient.rawExecutions).isEqualTo(1);
    }

    @Test
    void rawGuardedPipelineShouldFailClosedWhenModelOmitsAction() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.entityError = new IllegalStateException("schema mismatch");
        llmClient.rawResponse = """
                {
                  "reasoning": "The model omitted the action field.",
                  "riskScore": 0.1
                }
                """;

        UniversalPipelineExecutor executor = buildExecutor(llmClient);

        SecurityDecisionResponse response = executor.execute(
                        buildRequest(),
                        PipelineConfiguration.createPipelineConfig(),
                        SecurityDecisionResponse.class)
                .block();

        assertThat(response).isNotNull();
        assertThat(response.getAction()).isEqualTo("CHALLENGE");
        assertThat(response.getMetadata("securityDecisionParsingFallbackApplied", Boolean.class)).isTrue();
        assertThat(response.getMetadata("syntheticSecurityDecisionApplied", Boolean.class)).isTrue();
        assertThat(llmClient.entityExecutions).isZero();
        assertThat(llmClient.rawExecutions).isEqualTo(1);
    }

    private UniversalPipelineExecutor buildExecutor(RecordingLlmClient llmClient) {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                properties);
        PromptGenerator promptGenerator = new PromptGenerator(List.of(template));
        promptGenerator.registerTemplate(SecurityDecisionRequest.TEMPLATE_TYPE.name(), template);

        ContextRetrieverRegistry retrieverRegistry = new ContextRetrieverRegistry(new EmptyContextRetriever());
        return new UniversalPipelineExecutor(
                new ContextRetrievalStep(retrieverRegistry),
                new PreprocessingStep(),
                new PromptGenerationStep(promptGenerator),
                new LLMExecutionStep(llmClient),
                null,
                new ResponseParsingStep(),
                new PostprocessingStep(Optional.of(List.of(new SecurityDecisionResponseProcessor()))));
    }

    private SecurityDecisionRequest buildRequest() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("pipeline-security-decision-001")
                .timestamp(LocalDateTime.of(2026, 4, 18, 14, 10))
                .userId("alice")
                .sessionId("session-entity-only")
                .sourceIp("203.0.113.10")
                .description("POST /api/customer/export")
                .metadata(new LinkedHashMap<>(Map.of(
                        "httpMethod", "POST",
                        "requestPath", "/api/customer/export",
                        "resourceSensitivity", "HIGH",
                        "effectiveRoles", List.of("USER", "MANAGER"),
                        "effectivePermissions", List.of("customer.export"),
                        "mfaVerified", true)))
                .build();

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext =
                new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-entity-only");
        sessionContext.setRecentActions(List.of(
                "14:08 | MFA_COMPLETED",
                "14:09 | POST /api/customer/export"));

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());
        behaviorAnalysis.setBaselineEstablished(false);

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of()));
        request.withParameter("requestedModelId", "gpt-4o-mini");
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());
        request.withParameter("strictResponsePostprocessing", true);
        return request;
    }

    private static final class EmptyContextRetriever extends ContextRetriever {

        private EmptyContextRetriever() {
            super((VectorStore) null, new ContexaRagProperties());
        }

        @Override
        public ContextRetrievalResult retrieveContext(AIRequest<? extends DomainContext> request) {
            return new ContextRetrievalResult("", List.<Document>of(), Map.of("documentsFound", 0));
        }
    }

    private static final class RecordingLlmClient implements LLMClient, LLMOperations {

        private int rawExecutions;
        private int entityExecutions;
        private String rawResponse = "raw-response";
        private SecurityDecisionResponseLite entityResponse;
        private Throwable entityError;

        @Override
        public Mono<String> execute(ExecutionContext context) {
            rawExecutions++;
            return Mono.just(rawResponse);
        }

        @Override
        public Flux<String> stream(ExecutionContext context) {
            return Flux.just("stream-response");
        }

        @Override
        public <T> Mono<T> executeEntity(ExecutionContext context, Class<T> targetType) {
            entityExecutions++;
            if (entityError != null) {
                return Mono.error(entityError);
            }
            return Mono.just(targetType.cast(entityResponse));
        }

        @Override
        public Mono<String> call(Prompt prompt) {
            rawExecutions++;
            return Mono.just("legacy-response");
        }

        @Override
        public <T> Mono<T> entity(Prompt prompt, Class<T> targetType) {
            entityExecutions++;
            if (entityError != null) {
                return Mono.error(entityError);
            }
            return Mono.just(targetType.cast(entityResponse));
        }

        @Override
        public Flux<String> stream(Prompt prompt) {
            return Flux.just("legacy-stream-response");
        }
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
}
