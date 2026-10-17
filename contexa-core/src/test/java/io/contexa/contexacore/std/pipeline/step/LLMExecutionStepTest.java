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
package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.ObservedPromptTokenUsageRegistry;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptCompressionLedger;
import io.contexa.contexacore.std.components.prompt.PromptEvidenceCompleteness;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.LLMOperations;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionRawOutputContractInspector;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.UserMessage;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFact;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.context.decision.PolicyReason;
import io.contexa.contexacore.autonomous.context.decision.PolicySatisfaction;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptSections;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import java.util.LinkedHashMap;
import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class LLMExecutionStepTest {

    @Test
    void executeShouldBuildExecutionContextWithCanonicalRuntimeSelectionOptions() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-runtime-selection");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));

        TestContext domainContext = new TestContext();
        domainContext.setUserId("user-1");
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("requestedModelId", "qwen3:8b");
        request.withParameter("temperature", 0.0d);
        request.withParameter("topP", 0.2d);
        request.withParameter("seed", 7);
        request.withParameter("maxTokens", 96);
        request.withParameter("openAiReasoningEffort", "minimal");
        request.withParameter("openAiVerbosity", "low");
        request.withParameter("disableRetries", true);
        request.withParameter("disableOllamaThinking", true);
        request.withParameter("decisionBoundaryMode", "RUNTIME_MODEL_SELECTION");

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo("raw-response");
        assertThat(llmClient.lastExecutionContext).isNotNull();
        assertThat(llmClient.lastExecutionContext.getPreferredModel()).isEqualTo("qwen3:8b");
        assertThat(llmClient.lastExecutionContext.getTemperature()).isEqualTo(0.0d);
        assertThat(llmClient.lastExecutionContext.getTopP()).isEqualTo(0.2d);
        assertThat(llmClient.lastExecutionContext.getSeed()).isEqualTo(7);
        assertThat(llmClient.lastExecutionContext.getMaxTokens()).isEqualTo(96);
        assertThat(llmClient.lastExecutionContext.getMetadata())
                .containsEntry("requestedModelId", "qwen3:8b")
                .containsEntry("preferredModel", "qwen3:8b")
                .containsEntry("runtimeModelId", "qwen3:8b")
                .containsEntry("requestedModelSourceKey", "requestedModelId")
                .containsEntry("temperature", 0.0d)
                .containsEntry("topP", 0.2d)
                .containsEntry("seed", 7)
                .containsEntry("maxTokens", 96)
                .containsEntry("disableRetries", true)
                .containsEntry("disableOllamaThinking", true)
                .containsEntry("decisionBoundaryMode", "RUNTIME_MODEL_SELECTION");
        assertThat(context.getMetadata("requestedModelId", String.class)).isEqualTo("qwen3:8b");
        assertThat(context.getMetadata("temperature", Double.class)).isEqualTo(0.0d);
        assertThat(context.getMetadata("topP", Double.class)).isEqualTo(0.2d);
        assertThat(context.getMetadata("seed", Integer.class)).isEqualTo(7);
        assertThat(context.getMetadata("maxTokens", Integer.class)).isEqualTo(96);
        assertThat(context.getMetadata("disableRetries", Boolean.class)).isTrue();
        assertThat(context.getMetadata("disableOllamaThinking", Boolean.class)).isTrue();
        assertThat(llmClient.rawExecutions).isEqualTo(1);
        assertThat(llmClient.entityExecutions).isZero();
    }

    @Test
    void executeShouldSendPromptGenerationResultPromptObjectToLlmClientWithoutRebuildingIt() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-raw-identity-to-llm");
        String rawSystemPrompt = "RAW SYSTEM PROMPT";
        String rawUserPrompt = "=== CURRENT REQUEST AND EVENT ===\nTenantId: demo\nRequestPath: /admin/api/enterprise/verification/runtime/probe/normal/resource-001";
        Prompt finalPrompt = new Prompt(rawSystemPrompt + "\n" + rawUserPrompt);
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(
                        finalPrompt,
                        rawSystemPrompt,
                        rawUserPrompt,
                        rawSystemPrompt,
                        rawUserPrompt,
                        Map.of("promptTransformationMode", "IDENTITY", "promptRawTruthParity", true),
                        null));

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo("raw-response");
        assertThat(llmClient.lastExecutionContext).isNotNull();
        assertThat(llmClient.lastExecutionContext.getPrompt()).isSameAs(finalPrompt);
        assertThat(llmClient.lastExecutionContext.getPrompt().getContents()).contains(rawSystemPrompt);
        assertThat(llmClient.lastExecutionContext.getPrompt().getContents()).contains(rawUserPrompt);
    }

    @Test
    void executeShouldUseRawGuardedExecutionForSecurityDecisionTargets() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Verified identity and scope support the request.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-security-decision-raw");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        TestContext domainContext = new TestContext();
        domainContext.setUserId("user-1");
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("requestedModelId", "qwen3:8b");
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo(llmClient.rawResponse);
        assertThat(context.getMetadata("structuredOutputComplete", Boolean.class)).isFalse();
        assertThat(context.getMetadata("structuredOutputPolicy", String.class)).isEqualTo(StructuredOutputPolicy.RAW_FORBIDDEN.name());
        assertThat(context.getMetadata("structuredOutputMode", String.class)).isEqualTo("SECURITY_DECISION_RAW_GUARDED");
        assertThat(context.getMetadata("entityExecutionAttempted", Boolean.class)).isFalse();
        assertThat(context.getMetadata("entityExecutionSucceeded", Boolean.class)).isFalse();
        assertThat(context.getMetadata("rawExecutionAttempted", Boolean.class)).isTrue();
        assertThat(context.getMetadata("rawExecutionSucceeded", Boolean.class)).isTrue();
        assertThat(llmClient.rawExecutions).isEqualTo(1);
        assertThat(llmClient.entityExecutions).isZero();
        assertThat(llmClient.lastExecutionContext.getAdvisors()).isEmpty();
    }

    @Test
    void securityDecisionShouldRetryActualRawPipelineWhenActionIsMissing() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"reasoning\":\"Authorization allows this request.\"}";
        llmClient.secondRawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Authorization allows this request.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext(
                "exec-security-parser-retry",
                "VerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\nAuthorizationEffect: ALLOW");
        Object response = step.execute(securityRequest(), context).block();
        assertThat(response).isEqualTo(llmClient.secondRawResponse);
        assertThat(llmClient.rawExecutions).isEqualTo(2);
        assertThat(context.getMetadata("securityDecisionOutputRetryAttempted", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionOutputRetrySucceeded", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionInitialParseFailureCategory", String.class))
                .isEqualTo("ACTION_MISSING");
        assertThat(context.getMetadata("securityDecisionInitialFallbackAction", String.class))
                .isEqualTo("CHALLENGE");
    }

    @Test
    void securityDecisionShouldRetryActualRawPipelineOnLowRiskBoundaryChallenge() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"CHALLENGE\",\"reasoning\":\"Fresh verification is required before allowing access.\"}";
        llmClient.secondRawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Authorization and same-resource RAG support access.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext(
                "exec-security-semantic-retry",
                "VerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\nAuthorizationEffect: ALLOW");
        Object response = step.execute(securityRequest(), context).block();
        assertThat(response).isEqualTo(llmClient.secondRawResponse);
        assertThat(llmClient.rawExecutions).isEqualTo(2);
        assertThat(context.getMetadata("securityDecisionOutputRetryAttempted", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionOutputRetrySucceeded", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionInitialSemanticViolation", String.class))
                .isEqualTo("REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH");
        assertThat(context.getMetadata("securityDecisionInitialProposedAction", String.class))
                .isEqualTo("CHALLENGE");
    }

    @Test
    void securityDecisionShouldRetryBlockWithoutDecisiveEvidence() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"BLOCK\",\"reasoning\":\"Weak MFA and provisional baseline justify blocking.\"}";
        llmClient.secondRawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Authorization and same-resource RAG support access.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext(
                "exec-security-low-risk-boundary-retry",
                "VerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\nAuthorizationEffect: ALLOW");

        Object response = step.execute(securityRequest(), context).block();

        assertThat(response).isEqualTo(llmClient.secondRawResponse);
        assertThat(llmClient.rawExecutions).isEqualTo(2);
        assertThat(context.getMetadata("securityDecisionOutputRetrySucceeded", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionInitialSemanticViolation", String.class))
                .isEqualTo("BLOCK_WITHOUT_DECISIVE_EVIDENCE");
        assertThat(context.getMetadata("securityDecisionInitialProposedAction", String.class))
                .isEqualTo("BLOCK");
    }
    @Test
    void securityDecisionShouldNotRetryLegitimateVerificationChallenge() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"CHALLENGE\",\"reasoning\":\"Fresh verification is required before allowing access.\"}";
        llmClient.secondRawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Unexpected second response.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext(
                "exec-security-legitimate-challenge",
                "VerificationRequired: true\nMfaVerified: false\nSensitivity: HIGH\nAuthorizationEffect: ALLOW");
        Object response = step.execute(securityRequest(), context).block();
        assertThat(response).isEqualTo(llmClient.rawResponse);
        assertThat(llmClient.rawExecutions).isEqualTo(1);
        assertThat(context.getMetadata("securityDecisionOutputRetryAttempted", Boolean.class)).isNull();
    }

    @Test
    void securityDecisionShouldFailTheRetryAuditWhenContradictionPersists() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"CHALLENGE\",\"reasoning\":\"Fresh verification is required before allowing access.\"}";
        llmClient.secondRawResponse = "{\"action\":\"CHALLENGE\",\"reasoning\":\"Fresh verification required for this request.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext(
                "exec-security-persistent-contradiction",
                "VerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\nAuthorizationEffect: ALLOW");
        Object response = step.execute(securityRequest(), context).block();
        assertThat(response).isEqualTo("");
        assertThat(llmClient.rawExecutions).isEqualTo(2);
        assertThat(context.getMetadata("securityDecisionOutputRetryAttempted", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionOutputRetrySucceeded", Boolean.class)).isFalse();
        assertThat(context.getMetadata("securityDecisionOutputRetryFailureReason", String.class))
                .isEqualTo("REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH");
    }

    @Test
    void securityDecisionContractViolationAfterRetryIsRecordedAsValidationFailure() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        String ragClaim = "{\"action\":\"ALLOW\",\"reasoning\":\"Authorization allows access, and authorized RAG is relevant to the same resource.\"}";
        llmClient.rawResponse = ragClaim;
        llmClient.secondRawResponse = ragClaim;
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext(
                "exec-security-rag-claim-persists",
                "VerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\nAuthorizationEffect: ALLOW"
                        + "\nRagRelevance: NO_DOCUMENTS\nRagAuthorizedDocumentCount: 0");

        Object response = step.execute(securityRequest(), context).block();

        assertThat(response).isEqualTo("");
        assertThat(llmClient.rawExecutions).isEqualTo(2);
        assertThat(context.getMetadata("securityDecisionOutputRetryFailureReason", String.class))
                .isEqualTo("FALSE_AUTHORIZED_RAG_CLAIM");
        assertThat(context.getMetadata("securityDecisionParseFailureCategory", String.class)).isEqualTo("VALIDATION_FAILED");
        assertThat(context.getMetadata("structuredOutputFailureCategory", String.class)).isEqualTo("VALIDATION_FAILED");
    }

    /** W4-5: a retry tells the model what was wrong: its previous answer and the violation follow the same prompt. */
    @Test
    void aRetryTellsTheModelWhatWasWrong() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"reasoning\":\"Authorization allows this request.\"}";
        llmClient.secondRawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Authorization allows this request.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext("exec-w45-feedback",
                "VerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\nAuthorizationEffect: ALLOW");

        Object response = step.execute(securityRequest(), context).block();

        assertThat(response).isEqualTo(llmClient.secondRawResponse);
        List<Message> first = llmClient.executionContexts.get(0).getPrompt().getInstructions();
        List<Message> retry = llmClient.executionContexts.get(1).getPrompt().getInstructions();
        assertThat(retry).hasSize(first.size() + 2);
        assertThat(retry.subList(0, first.size())).isEqualTo(first);
        assertThat(retry.get(first.size())).isInstanceOf(AssistantMessage.class);
        assertThat(retry.get(first.size()).getText()).isEqualTo(llmClient.rawResponse);
        assertThat(retry.get(first.size() + 1)).isInstanceOf(UserMessage.class);
        assertThat(retry.get(first.size() + 1).getText()).contains("PARSER_ACTION_MISSING");
    }

    /** W4-5: an answer cut at the output limit is asked again once, with the same prompt and twice the limit. */
    @Test
    void aTruncatedAnswerIsAskedAgainWithTwiceTheOutputLimit() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"AL";
        llmClient.firstFinishReason = "length";
        llmClient.secondRawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Authorization allows this request.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext("exec-w45-length", "AuthorizationEffect: ALLOW");
        AIRequest<TestContext> request = securityRequest();
        request.withParameter("platformSecurityDecisionMaxTokens", 256);

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo(llmClient.secondRawResponse);
        assertThat(llmClient.executionContexts.get(0).getMaxTokens()).isEqualTo(256);
        assertThat(llmClient.executionContexts.get(1).getMaxTokens()).isEqualTo(512);
        assertThat(llmClient.executionContexts.get(1).getPrompt().getInstructions())
                .isEqualTo(llmClient.executionContexts.get(0).getPrompt().getInstructions());
        assertThat(context.getMetadata("securityDecisionOutputRetryReason", String.class)).isEqualTo("OUTPUT_TRUNCATED");
    }

    /**
     * N-OUT-2: a reasoning model can spend the whole output limit reasoning; the provider then ends at the limit
     * with no text, which the orchestrator fails as an empty answer. That answer is cut too: it is asked again once,
     * with the same prompt and twice the limit.
     */
    @Test
    void anAnswerCutAtTheOutputLimitBeforeAnyTextIsAskedAgainWithTwiceTheOutputLimit() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.firstFinishReason = "length";
        llmClient.firstRawError = new IllegalStateException("LLM response is null or empty - RequestId: exec-nout2");
        llmClient.secondRawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Authorization allows this request.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext("exec-nout2-length", "AuthorizationEffect: ALLOW");
        AIRequest<TestContext> request = securityRequest();
        request.withParameter("platformSecurityDecisionMaxTokens", 256);

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo(llmClient.secondRawResponse);
        assertThat(llmClient.executionContexts).hasSize(2);
        assertThat(llmClient.executionContexts.get(0).getMaxTokens()).isEqualTo(256);
        assertThat(llmClient.executionContexts.get(1).getMaxTokens()).isEqualTo(512);
        assertThat(llmClient.executionContexts.get(1).getPrompt().getInstructions())
                .isEqualTo(llmClient.executionContexts.get(0).getPrompt().getInstructions());
        assertThat(context.getMetadata("securityDecisionOutputRetryReason", String.class)).isEqualTo("OUTPUT_TRUNCATED");
        assertThat(context.getMetadata("securityDecisionOutputRetrySucceeded", Boolean.class)).isTrue();
    }

    /** N-OUT-2: the call again is the one retry; cut before any text again, it fails as an empty answer does. */
    @Test
    void anAnswerCutBeforeAnyTextTwiceIsAskedAgainOnce() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.firstFinishReason = "length";
        llmClient.rawError = new IllegalStateException("LLM response is null or empty - RequestId: exec-nout2-twice");
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext("exec-nout2-twice", "AuthorizationEffect: ALLOW");
        AIRequest<TestContext> request = securityRequest();
        request.withParameter("platformSecurityDecisionMaxTokens", 256);

        Object response = step.execute(request, context).block();

        assertThat(llmClient.executionContexts).hasSize(2);
        assertThat(llmClient.executionContexts.get(1).getMaxTokens()).isEqualTo(512);
        assertThat(response).isEqualTo("");
        assertThat(context.getMetadata("rawExecutionSucceeded", Boolean.class)).isFalse();
        assertThat(context.getMetadata("securityDecisionOutputRetrySucceeded", Boolean.class)).isFalse();
    }

    /** N-OUT-2 keeps: an empty answer the provider did not cut at the output limit fails at once, not asked again. */
    @Test
    void anEmptyAnswerNotCutAtTheOutputLimitIsNotAskedAgain() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.firstFinishReason = "stop";
        llmClient.firstRawError = new IllegalStateException("LLM response is null or empty - RequestId: exec-stop");
        llmClient.secondRawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Authorization allows this request.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext("exec-nout2-stop", "AuthorizationEffect: ALLOW");
        AIRequest<TestContext> request = securityRequest();
        request.withParameter("platformSecurityDecisionMaxTokens", 256);

        Object response = step.execute(request, context).block();

        assertThat(llmClient.executionContexts).hasSize(1);
        assertThat(response).isEqualTo("");
        assertThat(context.getMetadata("rawExecutionSucceeded", Boolean.class)).isFalse();
        assertThat(context.getMetadata("securityDecisionOutputRetryAttempted", Boolean.class)).isNull();
    }

    /**
     * N-OUT-3: every output retry is kept in the order it was asked, with why it was asked and whether its answer kept
     * the contract; the single retry fields keep the last one. An answer cut before any text is asked again with twice
     * the limit, and an answer that then breaks a rule is that retry failed on the rule (P8 N-OUT-2 host, N2A).
     */
    @Test
    void aTruncatedRetryWhoseAnswerBreaksARuleIsKeptWithItsReasonAndTheRule() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.firstFinishReason = "length";
        llmClient.firstRawError = new IllegalStateException("LLM response is null or empty - RequestId: exec-nout3");
        llmClient.secondRawResponse = "{\"action\":\"CHALLENGE\",\"reasoning\":\"Fresh verification required for this request.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext("exec-nout3-truncated",
                "VerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\nAuthorizationEffect: ALLOW");
        AIRequest<TestContext> request = securityRequest();
        request.withParameter("platformSecurityDecisionMaxTokens", 256);

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo("");
        assertThat(llmClient.executionContexts).hasSize(2);
        assertThat(context.getMetadata(PromptRuntimeTelemetrySupport.OUTPUT_RETRIES, List.class)).isEqualTo(List.of(
                Map.of("reason", "OUTPUT_TRUNCATED", "succeeded", false,
                        "failureReason", "REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH")));
        assertThat(context.getMetadata("securityDecisionOutputRetryReason", String.class)).isEqualTo("OUTPUT_TRUNCATED");
        assertThat(context.getMetadata("securityDecisionOutputRetrySucceeded", Boolean.class)).isFalse();
        assertThat(context.getMetadata("securityDecisionOutputRetryFailureReason", String.class))
                .isEqualTo("REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH");
    }

    /** N-OUT-3: a corrective retry whose answer keeps the contract is kept as succeeded, naming no rule. */
    @Test
    void aCorrectiveRetryThatSucceedsIsKeptWithItsReason() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"reasoning\":\"Authorization allows this request.\"}";
        llmClient.secondRawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Authorization allows this request.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext("exec-nout3-corrective",
                "VerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\nAuthorizationEffect: ALLOW");

        Object response = step.execute(securityRequest(), context).block();

        assertThat(response).isEqualTo(llmClient.secondRawResponse);
        assertThat(context.getMetadata(PromptRuntimeTelemetrySupport.OUTPUT_RETRIES, List.class))
                .isEqualTo(List.of(Map.of("reason", "PARSER_ACTION_MISSING", "succeeded", true)));
        assertThat(context.getMetadata("securityDecisionOutputRetryReason", String.class))
                .isEqualTo("PARSER_ACTION_MISSING");
    }

    /** N-OUT-3: a retry whose call fails is kept once, as failed and naming no rule. */
    @Test
    void aRetryWhoseCallFailsIsKeptOnceAsFailed() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.firstFinishReason = "length";
        llmClient.rawError = new IllegalStateException("LLM response is null or empty - RequestId: exec-nout3-twice");
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext("exec-nout3-twice", "AuthorizationEffect: ALLOW");
        AIRequest<TestContext> request = securityRequest();
        request.withParameter("platformSecurityDecisionMaxTokens", 256);

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo("");
        assertThat(llmClient.executionContexts).hasSize(2);
        assertThat(context.getMetadata(PromptRuntimeTelemetrySupport.OUTPUT_RETRIES, List.class))
                .isEqualTo(List.of(Map.of("reason", "OUTPUT_TRUNCATED", "succeeded", false)));
        assertThat(context.getMetadata("securityDecisionOutputRetrySucceeded", Boolean.class)).isFalse();
    }

    /** W4-6: a security decision runs with the platform's determinism settings, never the request's. */
    @Test
    void aSecurityDecisionRunsWithThePlatformDeterminismSettings() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Canonical facts support this request.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext("exec-w46-determinism", "AuthorizationEffect: ALLOW");
        AIRequest<TestContext> request = securityRequest();
        request.withParameter("temperature", 0.7d);
        request.withParameter("seed", 99);
        request.withParameter("platformDeterminismTemperature", 0.0d);
        request.withParameter("platformDeterminismSeed", 1);

        step.execute(request, context).block();

        assertThat(llmClient.lastExecutionContext.getTemperature()).isEqualTo(0.0d);
        assertThat(llmClient.lastExecutionContext.getSeed()).isEqualTo(1);
        assertThat(llmClient.lastExecutionContext.getMetadata()).doesNotContainEntry("decisionBoundaryMode",
                "RUNTIME_MODEL_SELECTION");
    }

    /** N-OUT-1 (G1-8): a security decision runs on the tier its layer put on the request. */
    @Test
    void aSecurityDecisionRunsOnTheTierOfItsLayer() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Canonical facts support this request.\"}";
        PipelineExecutionContext context = securityDecisionContext("exec-n-out-1-tier", "AuthorizationEffect: ALLOW");
        AIRequest<TestContext> request = securityRequest();
        request.withParameter("platformAnalysisTier", 2);

        new LLMExecutionStep(llmClient).execute(request, context).block();

        assertThat(llmClient.lastExecutionContext.getTier()).isEqualTo(2);
        assertThat(llmClient.lastExecutionContext.getMetadata()).doesNotContainEntry("decisionBoundaryMode",
                "RUNTIME_MODEL_SELECTION");
    }

    /** N-OUT-1 (G1-2): a re-call keeps the first answer, the retry answer and its action on the call record. */
    @Test
    void aReCallKeepsBothAnswersOnTheCallRecord() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        String first = "{\"action\":\"CHALLENGE\",\"reasoning\":\"Fresh verification is required before allowing access.\"}";
        String second = "{\"action\":\"CHALLENGE\",\"reasoning\":\"Fresh verification required for this request.\"}";
        llmClient.rawResponse = first;
        llmClient.secondRawResponse = second;
        PipelineExecutionContext context = securityDecisionContext("exec-n-out-1-recall",
                "VerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\nAuthorizationEffect: ALLOW");

        new LLMExecutionStep(llmClient).execute(securityRequest(), context).block();

        assertThat(context.getMetadata("securityDecisionInitialRawOutput", String.class)).isEqualTo(first);
        assertThat(context.getMetadata("securityDecisionRetryRawOutput", String.class)).isEqualTo(second);
        assertThat(context.getMetadata("securityDecisionRetryAction", String.class)).isEqualTo("CHALLENGE");
    }

    /** N-OUT-1 (G1-2): the provider's finish reason reaches the call record. */
    @Test
    void theProvidersFinishReasonReachesTheCallRecord() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Canonical facts support this request.\"}";
        llmClient.firstFinishReason = "stop";
        PipelineExecutionContext context = securityDecisionContext("exec-n-out-1-finish", "AuthorizationEffect: ALLOW");

        new LLMExecutionStep(llmClient).execute(securityRequest(), context).block();

        assertThat(context.getMetadata("providerFinishReason", String.class)).isEqualTo("stop");
    }

    /** N-OUT-1 (G1-1): a violation left after the retry records the fallback the broken rule asks for. */
    @Test
    void aViolationLeftAfterTheRetryRecordsTheFallbackTheRuleAsks() {
        RecordingLlmClient lowRisk = new RecordingLlmClient();
        lowRisk.rawResponse = "{\"action\":\"CHALLENGE\",\"reasoning\":\"Fresh verification is required before allowing access.\"}";
        lowRisk.secondRawResponse = "{\"action\":\"CHALLENGE\",\"reasoning\":\"Fresh verification required for this request.\"}";
        PipelineExecutionContext lowRiskContext = securityDecisionContext("exec-n-out-1-low-risk",
                "VerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\nAuthorizationEffect: ALLOW");
        RecordingLlmClient ragClaim = new RecordingLlmClient();
        String claim = "{\"action\":\"ALLOW\",\"reasoning\":\"Authorization allows access, and authorized RAG is relevant to the same resource.\"}";
        ragClaim.rawResponse = claim;
        ragClaim.secondRawResponse = claim;
        PipelineExecutionContext ragClaimContext = securityDecisionContext("exec-n-out-1-rag-claim",
                "VerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\nAuthorizationEffect: ALLOW"
                        + "\nRagRelevance: NO_DOCUMENTS\nRagAuthorizedDocumentCount: 0");

        new LLMExecutionStep(lowRisk).execute(securityRequest(), lowRiskContext).block();
        new LLMExecutionStep(ragClaim).execute(securityRequest(), ragClaimContext).block();

        assertThat(lowRiskContext.getMetadata(SecurityDecisionRawOutputContractInspector.CONTRACT_FALLBACK_ACTION,
                String.class)).isEqualTo("ALLOW");
        assertThat(ragClaimContext.getMetadata(SecurityDecisionRawOutputContractInspector.CONTRACT_FALLBACK_ACTION,
                String.class)).isEqualTo("ESCALATE");
    }

    /** W4-6: the call record carries the platform's determinism settings and the ones the provider did not take. */
    @Test
    void theCallRecordCarriesTheDeterminismTheProviderDidNotTake() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Canonical facts support this request.\"}";
        llmClient.determinismNotApplied = List.of("temperature");
        llmClient.providerReasoningEffort = "low";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext("exec-w46-record", "AuthorizationEffect: ALLOW");
        AIRequest<TestContext> request = securityRequest();
        request.withParameter("platformDeterminismTemperature", 0.0d);
        request.withParameter("platformDeterminismSeed", 1);

        step.execute(request, context).block();

        assertThat(context.getMetadata("platformDeterminismTemperature", Double.class)).isEqualTo(0.0d);
        assertThat(context.getMetadata("platformDeterminismSeed", Integer.class)).isEqualTo(1);
        assertThat(context.getMetadata(ExecutionContext.DETERMINISM_NOT_APPLIED, List.class))
                .isEqualTo(List.of("temperature"));
        assertThat(context.getMetadata(ExecutionContext.PROVIDER_REASONING_EFFORT, String.class)).isEqualTo("low");
    }

    /** W4-5 (plan 7): in enforce mode an answer weaker than a minimum action rule is retried with the rule it broke. */
    @Test
    void anEnforcedMinimumActionRuleIsRetriedWithTheRuleItBroke() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"The export looks routine.\"}";
        // P3 asks for a review (Q-87), so the corrected answer escalates.
        llmClient.secondRawResponse = "{\"action\":\"ESCALATE\",\"reasoning\":\"No approval covers the export.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext("exec-w45-enforce", "facts");

        Object response = step.execute(ruledRequest("ENFORCE"), context).block();

        assertThat(response).isEqualTo(llmClient.secondRawResponse);
        assertThat(llmClient.executionContexts).hasSize(2);
        List<Message> retry = llmClient.executionContexts.get(1).getPrompt().getInstructions();
        assertThat(retry.get(retry.size() - 1).getText()).contains("MIN_P3_POLICY_NOT_SATISFIED", "requires ESCALATE");
    }

    /** W4-5 (plan 7): in observe mode the rules are only recorded, so the answer is kept without a retry. */
    @Test
    void anObservedMinimumActionRuleIsNotRetried() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"The export looks routine.\"}";
        llmClient.secondRawResponse = "{\"action\":\"CHALLENGE\",\"reasoning\":\"No approval covers the export.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = securityDecisionContext("exec-w45-observe", "facts");

        Object response = step.execute(ruledRequest("OBSERVE"), context).block();

        assertThat(response).isEqualTo(llmClient.rawResponse);
        assertThat(llmClient.executionContexts).hasSize(1);
    }

    /** W4-8 (S-28): a v20 decision is checked on the facts its prompt was drawn from, then retried with what broke. */
    @Test
    void aV20DecisionIsCheckedOnTheFactsOfItsPrompt() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"CHALLENGE\",\"reasonCodes\":[{\"code\":\"BASELINE_MATCH\",\"fact\":\"F2\"}],"
                + "\"reason\":\"MFA is not verified.\"}";
        llmClient.secondRawResponse = "{\"action\":\"ALLOW\",\"reasonCodes\":[{\"code\":\"BASELINE_MATCH\",\"fact\":\"F2\"}],"
                + "\"reason\":\"The read is as usual.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = v20Context("exec-w48", V20_USER_PROMPT);

        Object response = step.execute(v20Request(), context).block();

        assertThat(response).isEqualTo(llmClient.secondRawResponse);
        List<Message> retry = llmClient.executionContexts.get(1).getPrompt().getInstructions();
        assertThat(retry.get(retry.size() - 1).getText()).contains("REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH");
    }

    private static final String V20_USER_PROMPT = """
            === SESSION (host) ===
            LoginMethod: PASSWORD, MFA not verified

            === REQUEST (host) ===
            ResourceClass: NORMAL

            === DECISION FACTS (computed) ===
            [F1] AuthorizationEffect: ALLOW
            [F2] SameAsBaseline: time, network as usual
            """;

    private static SecurityDecisionRequest v20Request() {
        CanonicalSecurityContext canonical = CanonicalSecurityContext.builder()
                .session(CanonicalSecurityContext.Session.builder().mfaVerified(false).build())
                .resource(CanonicalSecurityContext.Resource.builder().resourceClass("NORMAL").actionFamily("READ").build())
                .authorization(CanonicalSecurityContext.Authorization.builder().authorizationEffect("ALLOW").build())
                .decisionFacts(new DecisionFacts(List.of(new DecisionFact(null, "SameAsBaseline", "time, network as usual",
                        List.of("BASELINE_MATCH"), List.of(), DecisionFact.COMPUTED)), List.of(), PolicySatisfaction.UNKNOWN,
                        List.of()))
                .build();
        SecurityEvent event = SecurityEvent.builder().eventId("event-w48").metadata(new LinkedHashMap<>()).build();
        event.addMetadata("sealedEvidence.canonicalContext", canonical);
        return new SecurityDecisionRequest(new SecurityDecisionContext(event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(), null, List.of()));
    }

    private PipelineExecutionContext v20Context(String requestId, String userPrompt) {
        PipelineExecutionContext context = new PipelineExecutionContext(requestId);
        PromptExecutionMetadata metadata = PromptGovernanceSupport.buildExecutionMetadata(
                SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_V20_PROMPT_GOVERNANCE,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, List.of(), List.of(), List.of(), List.of(),
                PromptEvidenceCompleteness.SUFFICIENT, null, "system", userPrompt, "system", userPrompt,
                PromptCompressionLedger.identity("system", userPrompt),
                Map.of(PromptExecutionMetadata.USER_PROMPT_LAYOUT_VERSION, SecurityDecisionPromptSections.USER_PROMPT_LAYOUT_V20));
        context.addStepResult(PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt(userPrompt), "system", userPrompt, Map.of(), metadata));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);
        return context;
    }

    private static SecurityDecisionRequest ruledRequest(String mode) {
        CanonicalSecurityContext canonical = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder().resourceClass("CRITICAL").actionFamily("EXPORT").build())
                .decisionFacts(new DecisionFacts(List.of(), List.of(), new PolicySatisfaction(false, PolicyReason.NO_RECORD,
                        List.of(), "no approval for GB-500", List.of("EXPORT_APPROVAL")), List.of()))
                .build();
        SecurityEvent event = SecurityEvent.builder().eventId("event-w45").metadata(new LinkedHashMap<>()).build();
        event.addMetadata("sealedEvidence.canonicalContext", canonical);
        SecurityDecisionRequest request = new SecurityDecisionRequest(new SecurityDecisionContext(event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(), null, List.of()));
        request.withParameter("minimumActionMode", mode);
        request.withParameter("minimumActionSettings", MinimumActionRules.Settings.DEFAULTS);
        return request;
    }

    private PipelineExecutionContext securityDecisionContext(String requestId, String promptText) {
        PipelineExecutionContext context = new PipelineExecutionContext(requestId);
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt(promptText), "system", promptText, Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);
        return context;
    }

    private AIRequest<TestContext> securityRequest() {
        return new AIRequest<>(new TestContext(), new TemplateType("security"), new DiagnosisType("decision"));
    }
    /** P3-EXTRA-9: the platform's model call limit of a security decision reaches the execution context. */
    @Test
    void securityDecisionCarriesThePlatformCallLimitToTheProviderCall() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Canonical facts support this request.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-security-call-limit");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("call limit prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponse.class);
        AIRequest<TestContext> request = new AIRequest<>(new TestContext(), new TemplateType("security"),
                new DiagnosisType("decision"));
        request.withParameter("responseType", SecurityDecisionResponse.class);
        request.withParameter("platformSecurityDecisionCallTimeoutMs", 1500L);

        step.execute(request, context).block();

        assertThat(llmClient.lastExecutionContext.getMetadata())
                .containsEntry(ExecutionContext.CALL_TIMEOUT_MS, 1500L);
    }

    @Test
    void securityDecisionShouldIgnoreRuntimeOptionsAndApplyPlatformOutputLimit() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Canonical facts support this request.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-security-runtime-override-blocked");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponse.class);

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("responseType", SecurityDecisionResponse.class);
        request.withParameter("requestedModelId", "client-selected-model");
        request.withParameter("temperature", 0.0d);
        request.withParameter("topP", 0.2d);
        request.withParameter("seed", 7);
        request.withParameter("maxTokens", 96);
        request.withParameter("platformSecurityDecisionMaxTokens", 256);
        request.withParameter("openAiReasoningEffort", "minimal");
        request.withParameter("openAiVerbosity", "low");
        request.withParameter("disableRetries", true);
        request.withParameter("disableOllamaThinking", true);
        request.withParameter("decisionBoundaryMode", "RUNTIME_MODEL_SELECTION");

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo(llmClient.rawResponse);
        assertThat(llmClient.lastExecutionContext).isNotNull();
        assertThat(llmClient.lastExecutionContext.getPreferredModel()).isNull();
        assertThat(llmClient.lastExecutionContext.getTemperature()).isNull();
        assertThat(llmClient.lastExecutionContext.getTopP()).isNull();
        assertThat(llmClient.lastExecutionContext.getSeed()).isNull();
        assertThat(llmClient.lastExecutionContext.getMaxTokens()).isEqualTo(256);
        assertThat(llmClient.lastExecutionContext.getMetadata())
                .containsEntry("openAiReasoningEffort", "minimal")
                .containsEntry("openAiVerbosity", "low");
        assertThat(llmClient.lastExecutionContext.getMetadata())
                .containsEntry("maxTokens", 256)
                .doesNotContainKeys("requestedModelId", "preferredModel", "runtimeModelId", "temperature", "topP", "seed");
        assertThat(context.getMetadata("securityDecisionRuntimeOverrideIgnored", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionRuntimeOverrideIgnored.preferredModel", String.class)).isEqualTo("requestedModelId");
        assertThat(context.getMetadata("securityDecisionRuntimeOverrideIgnored.temperature", String.class)).isEqualTo("temperature");
        assertThat(context.getMetadata("securityDecisionRuntimeOverrideIgnored.maxTokens", String.class)).isEqualTo("maxTokens");
        assertThat(context.getMetadata("securityDecisionRuntimeOverrideIgnored.decisionBoundaryMode", String.class)).isEqualTo("decisionBoundaryMode");
    }

    /**
     * R4-L4: a security decision takes no model and no output limit from the request; the former verification pin is
     * an ignored override like any other, and the model call uses the configured model and the platform limit.
     */
    @Test
    void aSecurityDecisionTakesNoPinnedModelOrOutputLimitFromTheRequest() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Canonical facts support this request.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-security-no-pinned-model");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);
        AIRequest<TestContext> request = new AIRequest<>(new TestContext(), new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("officialVerificationPinnedModelId", "gpt-5-nano");
        request.withParameter("officialVerificationMaxTokens", 128);

        step.execute(request, context).block();

        assertThat(llmClient.lastExecutionContext.getPreferredModel()).isNull();
        assertThat(llmClient.lastExecutionContext.getMaxTokens()).isNull();
        assertThat(llmClient.lastExecutionContext.getMetadata())
                .doesNotContainEntry("requestedModelSourceKey", "officialVerificationPinnedModelId");
    }

    /** W4-2: the output schema the strategy asked for reaches the model call, and whether it went out comes back. */
    @Test
    void securityDecisionShouldPassTheOutputSchemaToTheModelCall() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Canonical facts support this request.\"}";
        llmClient.outputSchemaApplied = true;
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-security-output-schema");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponse.class);
        AIRequest<TestContext> request = new AIRequest<>(new TestContext(), new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("responseType", SecurityDecisionResponse.class);
        request.withParameter(ExecutionContext.OUTPUT_SCHEMA, "{\"type\":\"object\"}");

        step.execute(request, context).block();

        assertThat(llmClient.lastExecutionContext.getMetadata())
                .containsEntry(ExecutionContext.OUTPUT_SCHEMA, "{\"type\":\"object\"}");
        assertThat(context.getMetadata(ExecutionContext.OUTPUT_SCHEMA_APPLIED, Boolean.class)).isTrue();
    }

    /** W3-8: the prompt cache key the prompt step recorded reaches the model call, and whether it was sent comes back. */
    @Test
    void securityDecisionShouldPassThePromptCacheKeyToTheModelCall() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Canonical facts support this request.\"}";
        llmClient.promptCacheKeyApplied = true;
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-security-prompt-cache-key");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponse.class);
        context.addMetadata("promptCacheKey", "contexa-0123456789abcdef");
        AIRequest<TestContext> request = new AIRequest<>(new TestContext(), new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("responseType", SecurityDecisionResponse.class);

        step.execute(request, context).block();

        assertThat(llmClient.lastExecutionContext.getMetadata())
                .containsEntry("promptCacheKey", "contexa-0123456789abcdef");
        assertThat(context.getMetadata("promptCacheKeyApplied", Boolean.class)).isTrue();
    }

    @Test
    void executeShouldDeriveActualPromptBudgetTelemetryFromProviderUsage() {
        ObservedPromptTokenUsageRegistry.clear();
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Verified runtime evidence remained consistent.\"}";
        llmClient.actualPromptTokens = 930;
        llmClient.actualCompletionTokens = 42;
        llmClient.actualTotalTokens = 972;
        llmClient.actualTokenUsageAvailable = true;

        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-actual-token-usage");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);
        context.addMetadata("budgetMaxInputTokens", 1500);
        context.addMetadata("llmTotalPromptLength", 1860);
        // R4-L4: the calibration is kept under the model the provider answered with; no request pins it.
        context.addMetadata("providerResponseModel", "gpt-4o-mini");

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());

        try {
            Object response = step.execute(request, context).block();

            assertThat(response).isEqualTo(llmClient.rawResponse);
            assertThat(context.getMetadata("actualPromptTokens", Number.class)).isEqualTo(930);
            assertThat(context.getMetadata("actualPromptBudgetRemainingTokens", Number.class)).isEqualTo(570);
            assertThat(context.getMetadata("actualPromptBudgetExceeded", Boolean.class)).isFalse();
            assertThat(context.getMetadata("actualPromptUsageSource", String.class)).isEqualTo("PROVIDER_USAGE");
            assertThat(context.getMetadata("actualPromptBudgetUtilizationRate", Double.class)).isEqualTo(0.62d);
            assertThat(ObservedPromptTokenUsageRegistry.hasCalibration("gpt-4o-mini")).isTrue();
        } finally {
            ObservedPromptTokenUsageRegistry.clear();
        }
    }

    @Test
    void executeShouldBypassSecurityDecisionEntityFailureWithRawGuardedExecution() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.entityError = new IllegalStateException("schema mismatch");
        llmClient.rawResponse = "{\"action\":\"CHALLENGE\",\"reasoning\":\"Additional verification is required.\"}";
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-security-decision-failure");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("requestedModelId", "qwen3:8b");
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo(llmClient.rawResponse);
        assertThat(context.getMetadata("entityExecutionSucceeded", Boolean.class)).isFalse();
        assertThat(context.getMetadata("rawExecutionAttempted", Boolean.class)).isTrue();
        assertThat(context.getMetadata("rawExecutionSucceeded", Boolean.class)).isTrue();
        assertThat(llmClient.rawExecutions).isEqualTo(1);
        assertThat(llmClient.entityExecutions).isZero();
    }

    @Test
    void executeShouldReturnEmptyRawResultForSecurityDecisionRawExecutionFailure() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawError = new IllegalStateException("connection refused");
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-security-decision-raw-failure");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo("");
        assertThat(context.getMetadata("rawExecutionSucceeded", Boolean.class)).isFalse();
        assertThat(context.getMetadata("securityDecisionParseFailureCategory", String.class)).isEqualTo("MODEL_UNAVAILABLE");
        assertThat(context.getMetadata("securityDecisionFallbackReason", String.class)).isEqualTo("LLM_EXECUTION_FAILED");
        assertThat(llmClient.rawExecutions).isEqualTo(1);
        assertThat(llmClient.entityExecutions).isZero();
    }

    @Test
    void executeShouldUseValidatedConverterWhenNativeStructuredOutputIsDisabled() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        llmClient.rawResponse = "{\"action\":\"ALLOW\",\"reasoning\":\"Canonical facts support this request.\"}";
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction("ALLOW");
        lite.setConfidence(0.77d);
        lite.setRiskScore(0.14d);
        lite.setReasoning("Validated converter path preserved the structured security decision.");
        lite.setMitre("UNKNOWN");
        llmClient.entityResponse = lite;
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-native-disabled");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("aiGenerationType", SecurityDecisionResponseLite.class);

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));
        request.withParameter("nativeStructuredOutputEnabled", false);
        request.withParameter("structuredOutputPolicy", StructuredOutputPolicy.RAW_FORBIDDEN.name());

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo(llmClient.rawResponse);
        assertThat(context.getMetadata("structuredOutputMode", String.class))
                .isEqualTo("SECURITY_DECISION_RAW_GUARDED");
        assertThat(llmClient.lastExecutionContext.getAdvisors()).isEmpty();
        assertThat(llmClient.rawExecutions).isEqualTo(1);
        assertThat(llmClient.entityExecutions).isZero();
    }

    @Test
    void executeShouldResolveRuntimeModelIdAliasFromContextMetadata() {
        RecordingLlmClient llmClient = new RecordingLlmClient();
        LLMExecutionStep step = new LLMExecutionStep(llmClient);
        PipelineExecutionContext context = new PipelineExecutionContext("exec-runtime-model-id-alias");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PROMPT_GENERATION,
                new PromptGenerationResult(new Prompt("runtime selection prompt"), "system", "user", Map.of(), null));
        context.addMetadata("runtimeModelId", "qwen2.5:7b");

        TestContext domainContext = new TestContext();
        AIRequest<TestContext> request = new AIRequest<>(domainContext, new TemplateType("security"), new DiagnosisType("decision"));

        Object response = step.execute(request, context).block();

        assertThat(response).isEqualTo("raw-response");
        assertThat(llmClient.lastExecutionContext).isNotNull();
        assertThat(llmClient.lastExecutionContext.getPreferredModel()).isEqualTo("qwen2.5:7b");
        assertThat(llmClient.lastExecutionContext.getMetadata())
                .containsEntry("requestedModelId", "qwen2.5:7b")
                .containsEntry("runtimeModelId", "qwen2.5:7b")
                .containsEntry("requestedModelSourceKey", "runtimeModelId");
    }

    private static class RecordingLlmClient implements LLMClient, LLMOperations {

        private ExecutionContext lastExecutionContext;
        private final List<ExecutionContext> executionContexts = new ArrayList<>();
        private String firstFinishReason;
        private List<String> determinismNotApplied;
        private String providerReasoningEffort;
        private int rawExecutions;
        private int entityExecutions;
        private String rawResponse = "raw-response";
        private String secondRawResponse;
        private Throwable rawError;
        /** N-OUT-2: the error of the first call only; the calls after it answer as usual. */
        private Throwable firstRawError;
        private SecurityDecisionResponseLite entityResponse;
        private Throwable entityError;
        private Integer actualPromptTokens;
        private Integer actualCompletionTokens;
        private Integer actualTotalTokens;
        private Boolean actualTokenUsageAvailable;
        private Boolean promptCacheKeyApplied;
        private Boolean outputSchemaApplied;

        @Override
        public Mono<String> execute(ExecutionContext context) {
            this.lastExecutionContext = context;
            this.executionContexts.add(context);
            this.rawExecutions++;
            applyUsageMetadata(context);
            if (rawExecutions == 1 && firstFinishReason != null) {
                context.addMetadata("providerFinishReason", firstFinishReason);
            }
            if (determinismNotApplied != null) {
                context.addMetadata(ExecutionContext.DETERMINISM_NOT_APPLIED, determinismNotApplied);
            }
            if (providerReasoningEffort != null) {
                context.addMetadata(ExecutionContext.PROVIDER_REASONING_EFFORT, providerReasoningEffort);
            }
            if (rawExecutions == 1 && firstRawError != null) {
                return Mono.error(firstRawError);
            }
            if (rawError != null) {
                return Mono.error(rawError);
            }
            String response = rawExecutions > 1 && secondRawResponse != null ? secondRawResponse : rawResponse;
            return Mono.just(response);
        }

        @Override
        public Flux<String> stream(ExecutionContext context) {
            this.lastExecutionContext = context;
            return Flux.just("stream-response");
        }

        @Override
        public <T> Mono<T> executeEntity(ExecutionContext context, Class<T> targetType) {
            this.lastExecutionContext = context;
            this.entityExecutions++;
            applyUsageMetadata(context);
            if (entityError != null) {
                return Mono.error(entityError);
            }
            return Mono.just(targetType.cast(entityResponse));
        }

        @Override
        public Mono<String> call(Prompt prompt) {
            return Mono.just("legacy-response");
        }

        @Override
        public <T> Mono<T> entity(Prompt prompt, Class<T> targetType) {
            this.entityExecutions++;
            if (entityError != null) {
                return Mono.error(entityError);
            }
            return Mono.just(targetType.cast(entityResponse));
        }

        @Override
        public Flux<String> stream(Prompt prompt) {
            return Flux.just("legacy-stream-response");
        }

        private void applyUsageMetadata(ExecutionContext context) {
            if (context == null) {
                return;
            }
            if (actualPromptTokens != null) {
                context.addMetadata("actualPromptTokens", actualPromptTokens);
            }
            if (actualCompletionTokens != null) {
                context.addMetadata("actualCompletionTokens", actualCompletionTokens);
            }
            if (actualTotalTokens != null) {
                context.addMetadata("actualTotalTokens", actualTotalTokens);
            }
            if (actualTokenUsageAvailable != null) {
                context.addMetadata("actualTokenUsageAvailable", actualTokenUsageAvailable);
            }
            if (outputSchemaApplied != null) {
                context.addMetadata(ExecutionContext.OUTPUT_SCHEMA_APPLIED, outputSchemaApplied);
            }
            if (promptCacheKeyApplied != null) {
                context.addMetadata("promptCacheKeyApplied", promptCacheKeyApplied);
            }
        }
    }

    private static class TestContext extends DomainContext {
        @Override
        public String getDomainType() {
            return "test";
        }
    }
}
