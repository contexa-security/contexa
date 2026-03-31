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
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * sandbox 공식 benchmark 1단계.
 *
 * 실 HTTP/MFA/비동기 분석 경로를 반복 실행해 context/prompt 원본 품질을 통계로 남긴다.
 */
@SpringBootTest(
        classes = SpringBootStarterContexaApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({
        SandboxPromptTraceTestConfiguration.class,
        SandboxOttCaptureTestConfiguration.class,
        SandboxPromptSeedTestConfiguration.class
})
class SandboxFullStackPromptBenchmarkTest {

    private static final String DEFAULT_PASSWORD = "1234";
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(15);
    private static final Duration TRACE_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration ROUND_COOLDOWN = Duration.ofMillis(5_200);
    private static final int DEFAULT_SAMPLE_COUNT = 1;
    private static final int DEFAULT_ROUND_COUNT = 8;
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
    @DisplayName("공식 benchmark는 반복 웹 replay에서 95% 이상 품질과 0% contamination을 유지해야 한다")
    void shouldProduceFullStackBenchmarkStatisticsFromRepeatedWebReplay() throws Exception {
        int sampleCount = Integer.getInteger("sandbox.prompt.benchmark.samples", DEFAULT_SAMPLE_COUNT);
        int roundCount = Integer.getInteger("sandbox.prompt.benchmark.rounds", DEFAULT_ROUND_COUNT);
        String scenarioSelector = System.getProperty("sandbox.prompt.benchmark.scenarios", "CORE");
        SandboxPromptBenchmarkBatchRunner batchRunner = new SandboxPromptBenchmarkBatchRunner(replayHarness, objectMapper);
        List<SandboxPromptBenchmarkRunResult> runResults = batchRunner.execute(
                SandboxPromptReplayScenarioCatalog.resolve(scenarioSelector),
                sampleCount,
                roundCount,
                DEFAULT_PASSWORD);

        SandboxPromptBenchmarkReportWriter reportWriter = new SandboxPromptBenchmarkReportWriter(
                objectMapper,
                Path.of("build", "reports", "sandbox-fullstack-benchmark"));
        reportWriter.writeReport("Sandbox Full-Stack Context Prompt Benchmark", runResults);

        for (SandboxPromptBenchmarkRunResult runResult : runResults) {
            // 각 round는 실제 웹 경로에서 생성된 원본 trace를 검사하므로,
            // 여기서 95% 아래로 떨어지면 단순 노이즈가 아니라 컨텍스트/프롬프트 구현 결함으로 본다.
            assertThat(runResult.roundScorecards()).allSatisfy(scorecard ->
                    assertThat(scorecard.passRatePercent()).isGreaterThanOrEqualTo(95.0d));
            assertThat(runResult.traceContractAssessments()).allSatisfy(assessment ->
                    assertThat(assessment.complianceRate()).isGreaterThanOrEqualTo(95.0d));
            assertThat(runResult.promptFidelityAssessments()).allSatisfy(assessment ->
                    assertThat(assessment.fidelityRate()).isGreaterThanOrEqualTo(95.0d));
            assertThat(runResult.artifactIntegrityAssessments()).allSatisfy(assessment ->
                    assertThat(assessment.integrityRate()).isGreaterThanOrEqualTo(95.0d));

            // progression은 회차가 늘수록 relatedDocuments, baseline, prompt evidence가 누적된다는 뜻이다.
            // 이 점수가 떨어지면 3차가 2차보다, 2차가 1차보다 빈약해지는 역행이 생긴 것이다.
            assertThat(runResult.progressionScorecard().passRatePercent()).isGreaterThanOrEqualTo(95.0d);
            assertThat(runResult.metrics().get("Memory Artifact Integrity")).isGreaterThanOrEqualTo(95.0d);
            assertThat(runResult.metrics().get("Context Contamination Rate")).isLessThanOrEqualTo(0.0d);
            assertThat(runResult.defectFindings().stream()
                    .filter(finding -> finding.category() == SandboxPromptDefectCategory.IMPLEMENTATION_DEFECT)
                    .count()).isZero();
        }

        Map<String, SandboxPromptBenchmarkStatistics.Summary> summaries = summarize(runResults);
        assertThat(summaries.get("Event Integrity Rate").mean()).isGreaterThanOrEqualTo(95.0d);
        assertThat(summaries.get("Context Completeness Rate").mean()).isGreaterThanOrEqualTo(95.0d);
        assertThat(summaries.get("Context Consistency Rate").mean()).isGreaterThanOrEqualTo(95.0d);
        assertThat(summaries.get("Prompt Fidelity Rate").mean()).isGreaterThanOrEqualTo(95.0d);
        assertThat(summaries.get("Metadata Traceability Rate").mean()).isGreaterThanOrEqualTo(95.0d);
        assertThat(summaries.get("Trace Contract Compliance").mean()).isGreaterThanOrEqualTo(95.0d);
        assertThat(summaries.get("RAG Authorization Precision").mean()).isGreaterThanOrEqualTo(95.0d);
        assertThat(summaries.get("Memory Artifact Integrity").mean()).isGreaterThanOrEqualTo(95.0d);
        assertThat(summaries.get("Round Progression Integrity").mean()).isGreaterThanOrEqualTo(95.0d);
        assertThat(summaries.get("User-Specific Novelty Sensitivity").mean()).isGreaterThanOrEqualTo(95.0d);
        assertThat(summaries.get("Behavioral Surprise Resolution").mean()).isGreaterThanOrEqualTo(95.0d);
        assertThat(summaries.get("Context Contamination Rate").mean()).isLessThanOrEqualTo(0.0d);
    }

    private Map<String, SandboxPromptBenchmarkStatistics.Summary> summarize(List<SandboxPromptBenchmarkRunResult> runResults) {
        List<String> metricNames = runResults.stream()
                .flatMap(result -> result.metrics().keySet().stream())
                .distinct()
                .sorted()
                .toList();

        java.util.LinkedHashMap<String, SandboxPromptBenchmarkStatistics.Summary> summaries = new java.util.LinkedHashMap<>();
        for (String metricName : metricNames) {
            List<Double> values = runResults.stream()
                    .map(result -> result.metrics().get(metricName))
                    .filter(Objects::nonNull)
                    .toList();
            SandboxPromptBenchmarkMetricPolicy.MetricRule metricRule =
                    SandboxPromptBenchmarkMetricPolicy.ruleFor(metricName);
            summaries.put(metricName, SandboxPromptBenchmarkStatistics.summarize(
                    values,
                    metricRule.successThreshold(),
                    metricRule.higherIsBetter()));
        }
        return summaries;
    }
}
