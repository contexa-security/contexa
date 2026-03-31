package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RPI 전용 공식 증적 실행.
 *
 * 목적:
 * - 회차가 늘수록 relatedDocuments, baseline observation, history reference가 역행 없이 유지되는지 본다.
 * - 같은 계정이 수주간 반복 업무를 수행하다가 이상/회복 라운드를 거쳐도 이전 회차 기억이 사라지지 않아야 한다.
 */
@SpringBootTest(
        classes = SpringBootStarterContexaApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({
        SandboxPromptTraceTestConfiguration.class,
        SandboxOttCaptureTestConfiguration.class,
        SandboxPromptSeedTestConfiguration.class
})
class SandboxFullStackRpiBenchmarkTest {

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
    @DisplayName("RPI 전용 장기 horizon replay는 회차가 증가할수록 relatedDocuments와 baseline 관측치가 역행 없이 유지되어야 한다")
    void shouldProduceDedicatedRpiArtifactsFromLongHorizonReplay() throws Exception {
        SandboxPromptBenchmarkBatchRunner batchRunner = new SandboxPromptBenchmarkBatchRunner(replayHarness, objectMapper);
        List<SandboxPromptBenchmarkRunResult> runResults = batchRunner.execute(
                SandboxPromptReplayScenarioCatalog.resolve("EXTENDED"),
                SAMPLE_COUNT,
                ROUND_COUNT,
                DEFAULT_PASSWORD);

        SandboxPromptMetricReportWriter metricReportWriter = new SandboxPromptMetricReportWriter(
                objectMapper,
                Path.of("build", "reports", "sandbox-fullstack-benchmark", "RPI"));
        metricReportWriter.writeMetricReport(
                "Sandbox Full-Stack Context Prompt Benchmark - RPI",
                SandboxPromptBenchmarkMetricCatalog.ROUND_PROGRESSION_INTEGRITY,
                runResults);

        for (SandboxPromptBenchmarkRunResult runResult : runResults) {
            assertThat(runResult.metrics().get("Round Progression Integrity")).isGreaterThanOrEqualTo(95.0d);
        }
    }
}
