package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.pipeline.step.LLMExecutionStep;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
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
import org.springframework.ai.document.Document;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CoR 전용 공식 증적 실행.
 *
 * 목적:
 * - 실제 long-horizon replay에서 raw retrieval 후보에 foreign user / retrieval purpose mismatch가 섞이지 않는지 본다.
 * - 성공 기준은 "높을수록 좋음"이 아니라 contamination rate가 0.0으로 유지되는 것이다.
 */
@SpringBootTest(
        classes = SpringBootStarterContexaApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({
        SandboxPromptTraceTestConfiguration.class,
        SandboxOttCaptureTestConfiguration.class,
        SandboxPromptSeedTestConfiguration.class
})
class SandboxFullStackCorBenchmarkTest {

    private static final String DEFAULT_PASSWORD = "1234";
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(15);
    private static final Duration TRACE_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration ROUND_COOLDOWN = SandboxBenchmarkRuntimeSettings.roundCooldown();
    private static final int ROUND_COUNT = 24;
    private static final int SAMPLE_COUNT = 1;
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
    private io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository zeroTrustActionRepository;

    @Autowired
    private SandboxPromptUserProvisioner sandboxPromptUserProvisioner;

    @Autowired
    private SandboxVectorStoreIsolationSupport sandboxVectorStoreIsolationSupport;

    @Autowired
    private UnifiedVectorService unifiedVectorService;

    @MockBean(name = "llmExecutionStep")
    private LLMExecutionStep llmExecutionStep;

    private SandboxFullStackPromptReplayHarness replayHarness;

    @DynamicPropertySource
    static void registerSandboxDatasource(DynamicPropertyRegistry registry) {
        POSTGRESQL_SCHEMA_SUPPORT.register(registry);
        SandboxBenchmarkRuntimeSettings.registerSandboxBenchmarkProperties(registry);
        registry.add("sandbox.prompt.username", () -> "sandbox-seed-" + UUID.randomUUID() + "@example.com");
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
    @DisplayName("CoR 전용 장기 horizon replay는 raw retrieval 후보에 타 사용자 문서나 목적 불일치 문서가 섞이지 않아야 한다")
    void shouldProduceDedicatedCorArtifactsFromLongHorizonReplay() throws Exception {
        List<SandboxPromptBenchmarkRunResult> runResults = new ArrayList<>();
        List<SandboxPromptReplayScenario> scenarios = SandboxPromptReplayScenarioCatalog.resolve("EXTENDED");

        for (SandboxPromptReplayScenario scenario : scenarios) {
            replayHarness.prepareCleanReplayEnvironment();

            String targetUsername = String.format(
                    Locale.ROOT,
                    "benchmark-admin-%s-%03d@example.com",
                    scenario.scenarioKey().toLowerCase(Locale.ROOT).replace("_", "-"),
                    SAMPLE_COUNT);
            String distractorUsernameA = String.format(
                    Locale.ROOT,
                    "benchmark-foreign-a-%s-%03d@example.com",
                    scenario.scenarioKey().toLowerCase(Locale.ROOT).replace("_", "-"),
                    SAMPLE_COUNT);
            String distractorUsernameB = String.format(
                    Locale.ROOT,
                    "benchmark-foreign-b-%s-%03d@example.com",
                    scenario.scenarioKey().toLowerCase(Locale.ROOT).replace("_", "-"),
                    SAMPLE_COUNT);

            SandboxPromptReplayScenario seedScenario = SandboxPromptReplayScenarioCatalog.resizeScenario(scenario, 12);
            SandboxPromptReplayScenario targetScenario = SandboxPromptReplayScenarioCatalog.resizeScenario(scenario, ROUND_COUNT);

            replayHarness.replayScenarioWithoutEnvironmentReset(
                    distractorUsernameA,
                    DEFAULT_PASSWORD,
                    scenario.scenarioKey().toLowerCase(Locale.ROOT) + "-foreign-a-seed",
                    seedScenario);
            replayHarness.replayScenarioWithoutEnvironmentReset(
                    distractorUsernameB,
                    DEFAULT_PASSWORD,
                    scenario.scenarioKey().toLowerCase(Locale.ROOT) + "-foreign-b-seed",
                    seedScenario);

            seedWrongPurposeDocuments(targetUsername, scenario);

            SandboxPromptReplayRun targetRun = replayHarness.replayScenarioWithoutEnvironmentReset(
                    targetUsername,
                    DEFAULT_PASSWORD,
                    scenario.scenarioKey().toLowerCase(Locale.ROOT) + "-benchmark-run-" + SAMPLE_COUNT,
                    targetScenario);
            runResults.add(SandboxPromptBenchmarkMetricExtractor.evaluateRun(objectMapper, targetRun));
        }

        SandboxPromptMetricReportWriter metricReportWriter = new SandboxPromptMetricReportWriter(
                objectMapper,
                Path.of("build", "reports", "sandbox-fullstack-benchmark", "CoR"));
        metricReportWriter.writeMetricReport(
                "Sandbox Full-Stack Context Prompt Benchmark - CoR",
                SandboxPromptBenchmarkMetricCatalog.CONTEXT_CONTAMINATION_RATE,
                runResults);

        for (SandboxPromptBenchmarkRunResult runResult : runResults) {
            assertThat(runResult.metrics().get("Context Contamination Rate")).isLessThanOrEqualTo(0.0d);
        }
    }

    private void seedWrongPurposeDocuments(String targetUsername, SandboxPromptReplayScenario scenario) {
        List<SandboxPromptRoundPlan> roundPlans = scenario.roundPlans();
        int maxSeedCount = Math.min(3, roundPlans.size());
        for (int index = 0; index < maxSeedCount; index++) {
            SandboxPromptRoundPlan roundPlan = roundPlans.get(index);
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put(VectorDocumentMetadata.DOCUMENT_TYPE, VectorDocumentType.BEHAVIOR.getValue());
            metadata.put(VectorDocumentMetadata.SOURCE_TYPE, "behavior");
            metadata.put(VectorDocumentMetadata.ACCESS_SCOPE, "USER");
            metadata.put(VectorDocumentMetadata.USER_ID, targetUsername);
            metadata.put(VectorDocumentMetadata.RETRIEVAL_PURPOSE, "sandbox_wrong_purpose");
            metadata.put(VectorDocumentMetadata.ARTIFACT_ID, "wrong-purpose-" + scenario.scenarioKey().toLowerCase(Locale.ROOT) + "-" + index);
            metadata.put(VectorDocumentMetadata.ARTIFACT_VERSION, "1.0");
            metadata.put("requestPath", roundPlan.requestPath());
            metadata.put("sourceIp", roundPlan.clientIp());
            metadata.put("userAgentBrowser", roundPlan.simulatedUserAgentLabel());
            metadata.put("httpMethod", "GET");
            metadata.put("eventId", "wrong-purpose-seed-" + index);
            metadata.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

            String text = "Wrong purpose seed for " + targetUsername
                    + " on " + roundPlan.requestPath()
                    + " via GET from " + roundPlan.clientIp()
                    + " using " + roundPlan.simulatedUserAgentLabel()
                    + ". This document exists to prove that retrievalPurpose filtering blocks same-user but wrong-purpose memory.";
            unifiedVectorService.storeDocument(new Document(text, metadata));
        }
    }
}
