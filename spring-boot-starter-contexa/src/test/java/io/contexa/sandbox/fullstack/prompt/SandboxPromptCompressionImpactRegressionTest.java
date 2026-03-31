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

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(
        classes = SpringBootStarterContexaApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = "spring.main.allow-bean-definition-overriding=true")
@Import({
        SandboxPromptTraceTestConfiguration.class,
        SandboxOttCaptureTestConfiguration.class,
        SandboxPromptSeedTestConfiguration.class
})
class SandboxPromptCompressionImpactRegressionTest {

    private static final String DEFAULT_PASSWORD = "1234";
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(15);
    private static final Duration TRACE_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration ROUND_COOLDOWN = SandboxBenchmarkRuntimeSettings.roundCooldown();
    private static final int ROUND_COUNT = 24;
    private static final int SAMPLE_COUNT = 1;
    private static final String SCENARIO_SELECTOR = "DECISION_AMBIGUITY";
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
        registry.add("sandbox.prompt.username", () -> "sandbox-compression-seed-" + UUID.randomUUID() + "@example.com");
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
        System.clearProperty("sandbox.prompt.benchmark.profile");
        SandboxVectorStoreIsolationSupport.cleanupReplayArtifactsInDatabase();
        POSTGRESQL_SCHEMA_SUPPORT.dropQuietly();
    }

    @Test
    @DisplayName("compact prompt profile은 토큰을 줄이면서 CDC ERA SUHR를 실질적으로 악화시키지 않아야 한다")
    void shouldReducePromptLoadWithoutMaterialDecisionRegression() throws Exception {
        SandboxPromptCompressionImpactComparison expanded = executeComparison("CORTEX_L1_EXPANDED");
        SandboxPromptCompressionImpactComparison compact = executeComparison("CORTEX_L1_COMPACT");

        new SandboxPromptCompressionImpactReportWriter(
                objectMapper,
                Path.of("build", "reports", "sandbox-fullstack-benchmark", "compression-impact"))
                .write("expanded-vs-compact", expanded, compact);

        double expandedLength = averagePromptLength(expanded);
        double compactLength = averagePromptLength(compact);
        double expandedSavedTokens = averageSavedTokens(expanded);
        double compactSavedTokens = averageSavedTokens(compact);

        assertThat(compactLength).isLessThan(expandedLength);
        assertThat(compactSavedTokens).isGreaterThanOrEqualTo(expandedSavedTokens);
        assertThat(metricMean(compact, SandboxDecisionMetric.CDC.key()))
                .isGreaterThanOrEqualTo(metricMean(expanded, SandboxDecisionMetric.CDC.key()) - 3.0d);
        assertThat(metricMean(compact, SandboxDecisionMetric.ERA.key()))
                .isGreaterThanOrEqualTo(metricMean(expanded, SandboxDecisionMetric.ERA.key()) - 3.0d);
        assertThat(metricMean(compact, SandboxDecisionMetric.SUHR.key()))
                .isGreaterThanOrEqualTo(metricMean(expanded, SandboxDecisionMetric.SUHR.key()) - 3.0d);
        assertThat(metricMean(compact, SandboxDecisionMetric.CDC.key())).isGreaterThanOrEqualTo(95.0d);
        assertThat(metricMean(compact, SandboxDecisionMetric.ERA.key())).isGreaterThanOrEqualTo(95.0d);
        assertThat(metricMean(compact, SandboxDecisionMetric.SUHR.key())).isGreaterThanOrEqualTo(95.0d);

        Path reportDirectory = Path.of("build", "reports", "sandbox-fullstack-benchmark", "compression-impact");
        assertThat(reportDirectory.resolve("compression-impact-summary.json")).exists();
        assertThat(reportDirectory.resolve("compression-impact-summary.html")).exists();
        assertThat(reportDirectory.resolve("compression-impact-profiles.ndjson")).exists();
        assertThat(Files.readString(reportDirectory.resolve("compression-impact-summary.json")))
                .contains("decisionRegressionPass")
                .contains("compressionGainPass");
    }

    private SandboxPromptCompressionImpactComparison executeComparison(String budgetProfile) {
        String previousProfile = System.getProperty("sandbox.prompt.benchmark.profile");
        try {
            System.setProperty("sandbox.prompt.benchmark.profile", budgetProfile);
            SandboxPromptBenchmarkBatchRunner promptBatchRunner =
                    new SandboxPromptBenchmarkBatchRunner(replayHarness, objectMapper);
            List<SandboxPromptBenchmarkRunResult> promptRuns = promptBatchRunner.execute(
                    SandboxPromptReplayScenarioCatalog.resolve(SCENARIO_SELECTOR),
                    SAMPLE_COUNT,
                    ROUND_COUNT,
                    DEFAULT_PASSWORD);
            List<SandboxDecisionBenchmarkRunResult> decisionRuns = promptRuns.stream()
                    .map(promptRun -> SandboxDecisionMetricExtractor.evaluateRun(objectMapper, promptRun.replayRun()))
                    .toList();
            return new SandboxPromptCompressionImpactComparison(
                    budgetProfile,
                    SCENARIO_SELECTOR,
                    ROUND_COUNT,
                    promptRuns,
                    decisionRuns);
        } finally {
            if (previousProfile == null) {
                System.clearProperty("sandbox.prompt.benchmark.profile");
            } else {
                System.setProperty("sandbox.prompt.benchmark.profile", previousProfile);
            }
        }
    }

    private double averagePromptLength(SandboxPromptCompressionImpactComparison comparison) {
        return comparison.promptRunResults().stream()
                .flatMap(run -> run.replayRun().rounds().stream())
                .map(round -> round.snapshot() != null ? round.snapshot().promptExecutionMetadata() : null)
                .filter(java.util.Objects::nonNull)
                .mapToInt(metadata -> metadata.totalPromptLength())
                .average()
                .orElse(0.0d);
    }

    private double averageSavedTokens(SandboxPromptCompressionImpactComparison comparison) {
        return comparison.promptRunResults().stream()
                .flatMap(run -> run.replayRun().rounds().stream())
                .map(round -> round.snapshot() != null ? round.snapshot().promptExecutionMetadata() : null)
                .filter(java.util.Objects::nonNull)
                .mapToInt(metadata -> metadata.promptCompressionLedger().savedEstimatedTokens())
                .average()
                .orElse(0.0d);
    }

    private double metricMean(SandboxPromptCompressionImpactComparison comparison, String metricKey) {
        return comparison.decisionRunResults().stream()
                .map(run -> run.metrics().get(metricKey))
                .filter(java.util.Objects::nonNull)
                .mapToDouble(Double::doubleValue)
                .average()
                .orElse(0.0d);
    }
}
