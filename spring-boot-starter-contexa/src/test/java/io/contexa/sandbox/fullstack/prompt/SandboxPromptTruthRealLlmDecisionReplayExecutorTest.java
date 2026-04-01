package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.std.llm.config.LLMClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxPromptTruthRealLlmDecisionReplayExecutorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("real decision replay는 structured entity 응답을 우선 사용해야 한다")
    void shouldPreferStructuredEntityResponse() {
        RecordingLlmClient llmClient = new RecordingLlmClient(
                new io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite(),
                "{\"action\":\"ALLOW\",\"confidence\":0.42,\"reasoning\":\"raw fallback should not be used.\"}");
        llmClient.entityResponse().setAction("ALLOW");
        llmClient.entityResponse().setConfidence(0.42d);
        llmClient.entityResponse().setReasoning("Structured output matches the allowed action.");
        llmClient.entityResponse().setRiskScore(0.21d);
        llmClient.entityResponse().setMitre("UNKNOWN");

        SandboxPromptTruthRealLlmDecisionReplayExecutor executor =
                new SandboxPromptTruthRealLlmDecisionReplayExecutor(llmClient, objectMapper);

        SandboxPromptReplayRun replayRun = new SandboxPromptReplayRun(
                "decision-run-structured",
                "decision-user@example.com",
                "SCENARIO",
                "GROUP",
                SandboxPromptReplayScenarioCatalog.resizeScenario(
                        SandboxPromptReplayScenarioCatalog.ADMIN_SPARSE_HISTORY_THEN_HIGH_VALUE_REENTRY,
                        3),
                List.of(singleRound(1), singleRound(2), singleRound(3)));

        SandboxPromptReplayRun replayed = executor.replayDecisions(replayRun);
        SandboxDecisionTraceSnapshot snapshot = replayed.rounds().getFirst().decisionSnapshot();

        assertThat(snapshot.structuredOutputComplete()).isTrue();
        assertThat(snapshot.llmExecutionResult()).isInstanceOf(io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite.class);
        assertThat(String.valueOf(snapshot.llmRawResponse())).contains("\"action\":\"ALLOW\"");
        assertThat(snapshot.finalResponse()).isInstanceOf(io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite.class);

        io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite finalResponse =
                (io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite) snapshot.finalResponse();
        assertThat(finalResponse.getAction()).isEqualTo("ALLOW");
        assertThat(finalResponse.getConfidence()).isEqualTo(0.42d);
        assertThat(finalResponse.getReasoning()).isEqualTo("Structured output matches the allowed action.");
        assertThat(llmClient.entityCalls).isGreaterThanOrEqualTo(1);
        assertThat(llmClient.callCalls).isLessThanOrEqualTo(1);
    }

    @Test
    @DisplayName("structured entity가 비어 있으면 raw JSON fallback을 사용해야 한다")
    void shouldFallbackToRawJsonWhenStructuredEntityIsEmpty() {
        RecordingLlmClient llmClient = new RecordingLlmClient(
                new io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite(),
                "{\"action\":\"ESCALATE\",\"confidence\":0.58,\"reasoning\":\"Approval evidence remains ambiguous.\",\"riskScore\":0.64,\"mitre\":\"UNKNOWN\"}");

        SandboxPromptTruthRealLlmDecisionReplayExecutor executor =
                new SandboxPromptTruthRealLlmDecisionReplayExecutor(llmClient, objectMapper);

        SandboxPromptReplayRun replayRun = new SandboxPromptReplayRun(
                "decision-run-fallback",
                "decision-user@example.com",
                "SCENARIO",
                "GROUP",
                SandboxPromptReplayScenarioCatalog.resizeScenario(
                        SandboxPromptReplayScenarioCatalog.ADMIN_MIXED_SCOPE_THEN_APPROVAL_AMBIGUITY,
                        3),
                List.of(singleRound(1), singleRound(2), singleRound(3)));

        SandboxPromptReplayRun replayed = executor.replayDecisions(replayRun);
        SandboxDecisionTraceSnapshot snapshot = replayed.rounds().getFirst().decisionSnapshot();

        assertThat(snapshot.structuredOutputComplete()).isFalse();
        assertThat(snapshot.llmExecutionResult()).isInstanceOf(String.class);
        assertThat(String.valueOf(snapshot.llmRawResponse())).contains("\"action\":\"ESCALATE\"");
        io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite finalResponse =
                (io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite) snapshot.finalResponse();
        assertThat(finalResponse.getAction()).isEqualTo("ESCALATE");
        assertThat(finalResponse.getConfidence()).isEqualTo(0.58d);
        assertThat(llmClient.entityCalls).isGreaterThanOrEqualTo(1);
        assertThat(llmClient.callCalls).isGreaterThanOrEqualTo(1);
    }

    @Test
    @DisplayName("raw fallback가 빈 JSON이면 repair prompt로 재응답을 받아야 한다")
    void shouldRepairEmptyRawJsonFallback() {
        RecordingLlmClient llmClient = new RecordingLlmClient(
                new io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite(),
                "{}",
                "{\"action\":\"CHALLENGE\",\"confidence\":0.44,\"reasoning\":\"Baseline is sparse for this HIGH sensitivity access.\",\"riskScore\":0.55,\"mitre\":\"UNKNOWN\"}");

        SandboxPromptTruthRealLlmDecisionReplayExecutor executor =
                new SandboxPromptTruthRealLlmDecisionReplayExecutor(llmClient, objectMapper);

        SandboxPromptReplayRun replayRun = new SandboxPromptReplayRun(
                "decision-run-repair",
                "decision-user@example.com",
                "SCENARIO",
                "GROUP",
                SandboxPromptReplayScenarioCatalog.resizeScenario(
                        SandboxPromptReplayScenarioCatalog.ADMIN_SPARSE_HISTORY_THEN_HIGH_VALUE_REENTRY,
                        3),
                List.of(singleRound(1), singleRound(2), singleRound(3)));

        SandboxPromptReplayRun replayed = executor.replayDecisions(replayRun);
        SandboxDecisionTraceSnapshot snapshot = replayed.rounds().getFirst().decisionSnapshot();

        assertThat(snapshot.structuredOutputComplete()).isFalse();
        assertThat(String.valueOf(snapshot.llmRawResponse())).contains("\"action\":\"CHALLENGE\"");
        io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite finalResponse =
                (io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite) snapshot.finalResponse();
        assertThat(finalResponse.getAction()).isEqualTo("CHALLENGE");
        assertThat(finalResponse.getConfidence()).isEqualTo(0.44d);
        assertThat(finalResponse.getReasoning()).isEqualTo("Baseline is sparse for this HIGH sensitivity access.");
        assertThat(llmClient.callCalls).isGreaterThanOrEqualTo(2);
    }

    private SandboxPromptReplayRound singleRound(int roundNumber) {
        SandboxPromptRoundPlan roundPlan = SandboxPromptReplayScenarioCatalog
                .resizeScenario(SandboxPromptReplayScenarioCatalog.ADMIN_SPARSE_HISTORY_THEN_HIGH_VALUE_REENTRY, 3)
                .roundPlanForRound(roundNumber);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-r0" + roundNumber)
                .timestamp(LocalDateTime.of(2026, 4, 1, 12, roundNumber))
                .userId("decision-user")
                .sessionId("session-001")
                .sourceIp(roundPlan.clientIp())
                .description("AUTHORIZATION_METHOD")
                .build();
        event.addMetadata("requestId", "request-r0" + roundNumber);
        event.addMetadata("correlationId", "request-r0" + roundNumber);
        event.addMetadata("mfaVerified", true);
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("authorizationEffect", "ALLOW");
        event.addMetadata("requestPath", roundPlan.requestPath());

        SandboxPromptTraceSnapshot promptSnapshot = new SandboxPromptTraceSnapshot(
                "request-r0" + roundNumber,
                Instant.now(),
                event,
                null,
                null,
                List.of(),
                null,
                "Return JSON only.",
                "Path: " + roundPlan.requestPath(),
                Map.ofEntries(
                        Map.entry("promptVersion", "2026.04.01"),
                        Map.entry("promptHash", "sha256:test-" + roundNumber),
                        Map.entry("systemPromptHash", "sha256:system"),
                        Map.entry("userPromptHash", "sha256:user"),
                        Map.entry("rawPromptHash", "sha256:raw-" + roundNumber),
                        Map.entry("promptTransformationMode", "IDENTITY"),
                        Map.entry("budgetProfile", "CORTEX_L1_STANDARD"),
                        Map.entry("budgetViewProfile", "IDENTITY"),
                        Map.entry("estimatedTotalTokens", 128),
                        Map.entry("promptSectionSet", List.of("CURRENT_REQUEST_AND_EVENT")),
                        Map.entry("omittedSections", List.of())),
                null);

        return new SandboxPromptReplayRound(
                roundNumber == 1 ? "INITIAL" : "FOLLOW_UP",
                roundNumber,
                roundPlan,
                "request-r0" + roundNumber,
                roundPlan.requestPath(),
                roundPlan.clientIp(),
                roundPlan.simulatedUserAgentLabel(),
                "device-" + roundPlan.deviceAlias(),
                Map.of("requestId", "request-r0" + roundNumber),
                promptSnapshot,
                null);
    }

    private static final class RecordingLlmClient implements LLMClient {

        private final io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite entityResponse;
        private final List<String> callResponses;
        private int entityCalls;
        private int callCalls;

        private RecordingLlmClient(
                io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite entityResponse,
                String... callResponses) {
            this.entityResponse = entityResponse;
            this.callResponses = List.of(callResponses);
        }

        private io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite entityResponse() {
            return entityResponse;
        }

        @Override
        public Mono<String> call(org.springframework.ai.chat.prompt.Prompt prompt) {
            callCalls++;
            int index = Math.min(Math.max(callCalls - 1, 0), callResponses.size() - 1);
            return Mono.just(callResponses.get(index));
        }

        @Override
        @SuppressWarnings("unchecked")
        public <T> Mono<T> entity(org.springframework.ai.chat.prompt.Prompt prompt, Class<T> targetType) {
            entityCalls++;
            return Mono.just((T) entityResponse);
        }

        @Override
        public Flux<String> stream(org.springframework.ai.chat.prompt.Prompt prompt) {
            return Flux.empty();
        }
    }
}
