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
 * CCSR 전용 공식 증적 실행.
 *
 * 같은 replay라도 CCR 공용 결과를 재사용하지 않고, 컨텍스트 간 일관성만 따로 측정한
 * 독립 결과서를 남겨 심사 시 항목별 증적을 바로 제출할 수 있게 한다.
 */
@SpringBootTest(
        classes = SpringBootStarterContexaApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({
        SandboxPromptTraceTestConfiguration.class,
        SandboxOttCaptureTestConfiguration.class,
        SandboxPromptSeedTestConfiguration.class
})
class SandboxFullStackCcsrBenchmarkTest {

    private static final String DEFAULT_PASSWORD = "1234";
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(15);
    private static final Duration TRACE_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration ROUND_COOLDOWN = Duration.ofMillis(5_200);
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
    @DisplayName("CCSR 전용 장기 리플레이 공식 증적은 독립 파일명으로 95% 이상을 입증해야 한다")
    void shouldProduceDedicatedCcsrArtifactsFromLongHorizonReplay() throws Exception {
        // 동일 계정이 여러 주 동안 다양한 업무 패턴을 보이는 장기 리플레이를 실제 HTTP로 다시 실행한다.
        SandboxPromptBenchmarkBatchRunner batchRunner = new SandboxPromptBenchmarkBatchRunner(replayHarness, objectMapper);
        List<SandboxPromptBenchmarkRunResult> runResults = batchRunner.execute(
                SandboxPromptReplayScenarioCatalog.resolve("EXTENDED"),
                SAMPLE_COUNT,
                ROUND_COUNT,
                DEFAULT_PASSWORD);

        // 공용 summary를 재사용하지 않고 CCSR 전용 증적 파일을 별도 디렉터리에 기록한다.
        SandboxPromptMetricReportWriter metricReportWriter = new SandboxPromptMetricReportWriter(
                objectMapper,
                Path.of("build", "reports", "sandbox-fullstack-benchmark", "CCSR"));
        metricReportWriter.writeMetricReport(
                "Sandbox Full-Stack Context Prompt Benchmark - CCSR",
                SandboxPromptBenchmarkMetricCatalog.CONTEXT_CONSISTENCY_RATE,
                runResults);

        // 성공 기준: 같은 사실이 event/session/prompt 사이에서 서로 모순되지 않아야 한다.
        for (SandboxPromptBenchmarkRunResult runResult : runResults) {
            assertThat(runResult.metrics().get("Context Consistency Rate")).isGreaterThanOrEqualTo(95.0d);
        }
    }
}
