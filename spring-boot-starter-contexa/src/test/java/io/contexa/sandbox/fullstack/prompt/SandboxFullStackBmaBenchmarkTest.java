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
 * BMA 전용 공식 증적 실행.
 *
 * 목적:
 * - 첫 회차는 baseline 미성숙(PROVISIONAL/No baseline established)이어야 하고,
 * - 이후 회차는 observed work pattern context와 observation 증가가 이어져야 한다.
 */
@SpringBootTest(
        classes = SpringBootStarterContexaApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({
        SandboxPromptTraceTestConfiguration.class,
        SandboxOttCaptureTestConfiguration.class,
        SandboxPromptSeedTestConfiguration.class
})
class SandboxFullStackBmaBenchmarkTest {

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
    @DisplayName("BMA 전용 장기 horizon replay는 1차 provisional 이후 baseline 관측치가 회차가 늘수록 성숙해야 한다")
    void shouldProduceDedicatedBmaArtifactsFromLongHorizonReplay() throws Exception {
        SandboxPromptBenchmarkBatchRunner batchRunner = new SandboxPromptBenchmarkBatchRunner(replayHarness, objectMapper);
        List<SandboxPromptBenchmarkRunResult> runResults = batchRunner.execute(
                SandboxPromptReplayScenarioCatalog.resolve("EXTENDED"),
                SAMPLE_COUNT,
                ROUND_COUNT,
                DEFAULT_PASSWORD);

        SandboxPromptMetricReportWriter metricReportWriter = new SandboxPromptMetricReportWriter(
                objectMapper,
                Path.of("build", "reports", "sandbox-fullstack-benchmark", "BMA"));
        metricReportWriter.writeMetricReport(
                "Sandbox Full-Stack Context Prompt Benchmark - BMA",
                SandboxPromptBenchmarkMetricCatalog.BASELINE_MATURITY_ACCURACY,
                runResults);

        for (SandboxPromptBenchmarkRunResult runResult : runResults) {
            assertThat(runResult.metrics().get("Baseline Maturity Accuracy")).isGreaterThanOrEqualTo(95.0d);
        }
    }
}
