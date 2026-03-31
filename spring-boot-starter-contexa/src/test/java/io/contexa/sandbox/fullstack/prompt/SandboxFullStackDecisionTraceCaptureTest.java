package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.std.pipeline.step.LLMExecutionStep;
import io.contexa.sandbox.mfa.ott.SandboxOttCaptureTestConfiguration;
import io.contexa.sandbox.mfa.ott.SandboxOttCodeCapture;
import io.contexa.springbootstartercontexa.SpringBootStarterContexaApplication;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

import java.time.Duration;
import java.util.Map;
import java.util.Locale;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Decision-layer trace capture smoke test for CDC/ERA/SUHR P0.
 *
 * This does not evaluate decision quality yet.
 * It only proves that the real web replay path can return request-bound decision traces
 * after PostprocessingStep succeeds.
 */
@SpringBootTest(
        classes = SpringBootStarterContexaApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = "spring.main.allow-bean-definition-overriding=true")
@Import({
        SandboxPromptTraceTestConfiguration.class,
        SandboxOttCaptureTestConfiguration.class,
        SandboxPromptSeedTestConfiguration.class
})
class SandboxFullStackDecisionTraceCaptureTest {

    private static final String DEFAULT_PASSWORD = "1234";
    private static final String USERNAME = "sandbox-decision-" +
            UUID.randomUUID().toString().replace("-", "").substring(0, 12).toLowerCase(Locale.ROOT) +
            "@example.com";
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(15);
    private static final Duration TRACE_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration ROUND_COOLDOWN = SandboxBenchmarkRuntimeSettings.roundCooldown();
    private static final SandboxPostgresqlSchemaSupport POSTGRESQL_SCHEMA_SUPPORT =
            SandboxPostgresqlSchemaSupport.create();

    @LocalServerPort
    private int port;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SandboxOttCodeCapture sandboxOttCodeCapture;

    @Autowired
    private SandboxPromptTraceStore sandboxPromptTraceStore;

    @Autowired
    private SandboxDecisionTraceStore sandboxDecisionTraceStore;

    @Autowired
    private ZeroTrustActionRepository zeroTrustActionRepository;

    @Autowired
    private SandboxPromptUserProvisioner sandboxPromptUserProvisioner;

    @Autowired
    private SandboxVectorStoreIsolationSupport sandboxVectorStoreIsolationSupport;

    @MockBean(name = "llmExecutionStep")
    private LLMExecutionStep llmExecutionStep;

    private SandboxFullStackPromptReplayHarness replayHarness;

    @DynamicPropertySource
    static void registerSandboxDatasource(DynamicPropertyRegistry registry) {
        POSTGRESQL_SCHEMA_SUPPORT.register(registry);
        SandboxBenchmarkRuntimeSettings.registerSandboxBenchmarkProperties(registry);
        registry.add("sandbox.prompt.username", () -> USERNAME);
        registry.add("sandbox.prompt.password", () -> DEFAULT_PASSWORD);
    }

    @BeforeEach
    void setUp() {
        SandboxStableLlmBoundary.configure(objectMapper, llmExecutionStep);
        replayHarness = new SandboxFullStackPromptReplayHarness(
                "http://127.0.0.1:" + port,
                HTTP_TIMEOUT,
                TRACE_TIMEOUT,
                ROUND_COOLDOWN,
                objectMapper,
                sandboxOttCodeCapture,
                sandboxPromptTraceStore,
                sandboxDecisionTraceStore,
                zeroTrustActionRepository,
                sandboxPromptUserProvisioner,
                sandboxVectorStoreIsolationSupport);
    }

    @AfterAll
    static void tearDown() {
        SandboxVectorStoreIsolationSupport.cleanupReplayArtifactsInDatabase();
        POSTGRESQL_SCHEMA_SUPPORT.dropQuietly();
    }

    @Test
    @DisplayName("CDC/ERA/SUHR P0: 실제 웹 replay 이후 decision trace가 requestId 기준으로 회수되어야 한다")
    void shouldCaptureDecisionTraceAfterRealWebReplay() {
        SandboxPromptReplayRun replayRun = replayHarness.replayThreeRounds(
                USERNAME,
                DEFAULT_PASSWORD,
                "sandbox-decision-trace-" + UUID.randomUUID());

        for (SandboxPromptReplayRound round : replayRun.rounds()) {
            SandboxDecisionTraceSnapshot decisionSnapshot = round.decisionSnapshot();

            // 이 검증의 의미:
            // - prompt trace만이 아니라 decision-layer 산출물도 같은 requestId에 묶여 있어야
            //   이후 CDC/ERA/SUHR이 입력-출력 정합성을 평가할 수 있다.
            assertThat(decisionSnapshot).as("decision trace must be captured for round %s", round.roundNumber()).isNotNull();
            assertThat(decisionSnapshot.requestId()).isEqualTo(round.requestId());

            // prompt input truth와 decision trace가 같은 계약을 보고 있어야 한다.
            assertThat(decisionSnapshot.systemPrompt()).isEqualTo(round.snapshot().systemPrompt());
            assertThat(decisionSnapshot.userPrompt()).isEqualTo(round.snapshot().userPrompt());
            assertThat(decisionSnapshot.promptMetadata()).isEqualTo(round.snapshot().metadata());

            // CDC/ERA/SUHR은 LLM execution 결과, 파싱 결과, 최종 response를 모두 필요로 한다.
            assertThat(decisionSnapshot.llmExecutionResult()).isNotNull();
            assertThat(decisionSnapshot.parsedResponse()).isNotNull();
            assertThat(decisionSnapshot.finalResponse()).isNotNull();

            // prompt execution metadata와 pipeline metadata가 있어야 reasoning/uncertainty 분석이 가능하다.
            assertThat(decisionSnapshot.promptExecutionMetadata()).isNotNull();
            assertThat(decisionSnapshot.pipelineMetadata()).isNotEmpty();
            assertThat(decisionSnapshot.pipelineMetadata())
                    .containsKeys("executionId", "structuredOutputComplete", "llmExecutionResultClass", "finalResponseClass");

            Object structuredOutputComplete = decisionSnapshot.pipelineMetadata().get("structuredOutputComplete");
            assertThat(structuredOutputComplete).isEqualTo(Boolean.TRUE);

            @SuppressWarnings("unchecked")
            Map<String, Object> promptMetadata = (Map<String, Object>) (Map<?, ?>) decisionSnapshot.promptMetadata();
            assertThat(promptMetadata)
                    .containsKeys("promptVersion", "promptHash", "systemPromptHash", "userPromptHash", "promptSectionSet");
        }
    }
}
