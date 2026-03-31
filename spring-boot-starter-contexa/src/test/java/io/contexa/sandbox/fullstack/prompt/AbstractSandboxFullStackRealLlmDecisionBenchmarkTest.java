package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.sandbox.mfa.ott.SandboxOttCaptureTestConfiguration;
import io.contexa.sandbox.mfa.ott.SandboxOttCodeCapture;
import io.contexa.springbootstartercontexa.SpringBootStarterContexaApplication;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

@SpringBootTest(
        classes = SpringBootStarterContexaApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = "spring.main.allow-bean-definition-overriding=true")
@Import({
        SandboxPromptTraceTestConfiguration.class,
        SandboxOttCaptureTestConfiguration.class,
        SandboxPromptSeedTestConfiguration.class,
        SandboxDecisionRealLlmTestConfiguration.class
})
abstract class AbstractSandboxFullStackRealLlmDecisionBenchmarkTest {

    protected static final String DEFAULT_PASSWORD = "1234";
    protected static final Path REPORT_DIRECTORY = Path.of("build", "reports", "sandbox-fullstack-benchmark");
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration TRACE_TIMEOUT = Duration.ofSeconds(SandboxDecisionBenchmarkSettings.traceTimeoutSeconds());
    private static final Duration ROUND_COOLDOWN = SandboxBenchmarkRuntimeSettings.roundCooldown();
    private static final SandboxPostgresqlSchemaSupport POSTGRESQL_SCHEMA_SUPPORT =
            SandboxPostgresqlSchemaSupport.create();

    @LocalServerPort
    private int port;

    @Autowired
    protected ObjectMapper objectMapper;

    @Autowired
    private SandboxOttCodeCapture sandboxOttCodeCapture;

    @Autowired
    private SandboxPromptTraceStore sandboxPromptTraceStore;

    @Autowired
    private SandboxDecisionTraceStore sandboxDecisionTraceStore;

    @Autowired
    private SandboxDecisionEnforcementStore sandboxDecisionEnforcementStore;

    @Autowired
    private ZeroTrustActionRepository zeroTrustActionRepository;

    @Autowired
    private SandboxPromptUserProvisioner sandboxPromptUserProvisioner;

    @Autowired
    private SandboxVectorStoreIsolationSupport sandboxVectorStoreIsolationSupport;

    @Autowired
    protected SandboxPromptTruthRealLlmDecisionReplayExecutor sandboxPromptTruthRealLlmDecisionReplayExecutor;

    protected SandboxFullStackPromptReplayHarness replayHarness;

    @DynamicPropertySource
    static void registerSandboxDatasource(DynamicPropertyRegistry registry) {
        POSTGRESQL_SCHEMA_SUPPORT.register(registry);
        SandboxBenchmarkRuntimeSettings.registerSandboxBenchmarkProperties(registry);
        registry.add("sandbox.prompt.username", () -> "sandbox-decision-real-" + UUID.randomUUID() + "@example.com");
        registry.add("sandbox.prompt.password", () -> DEFAULT_PASSWORD);
        registry.add("contexa.opentelemetry.enabled", () -> false);
        registry.add("spring.ai.ollama.chat.options.model", SandboxDecisionBenchmarkSettings::pinnedModelId);
        registry.add("spring.ai.ollama.chat.options.temperature", SandboxDecisionBenchmarkSettings::temperature);
        registry.add("spring.ai.ollama.chat.options.num-predict", SandboxDecisionBenchmarkSettings::maxOutputTokens);
        registry.add("security.plane.llm-executor.core-pool-size",
                SandboxDecisionBenchmarkSettings::llmExecutorCorePoolSize);
        registry.add("security.plane.llm-executor.max-pool-size",
                SandboxDecisionBenchmarkSettings::llmExecutorMaxPoolSize);
        registry.add("security.plane.llm-executor.queue-capacity",
                SandboxDecisionBenchmarkSettings::llmExecutorQueueCapacity);
        registry.add("spring.ai.security.tiered.layer1.timeout.rag-ms",
                SandboxDecisionBenchmarkSettings::ragTimeoutMs);
        registry.add("spring.ai.vectorstore.pgvector.search-timeout-ms",
                SandboxDecisionBenchmarkSettings::searchTimeoutMs);
        registry.add("spring.ai.vectorstore.pgvector.store-timeout-ms",
                SandboxDecisionBenchmarkSettings::storeTimeoutMs);
    }

    @BeforeEach
    void setUpRealLlmReplayHarness() {
        replayHarness = new SandboxFullStackPromptReplayHarness(
                "http://127.0.0.1:" + port,
                HTTP_TIMEOUT,
                TRACE_TIMEOUT,
                ROUND_COOLDOWN,
                objectMapper,
                sandboxOttCodeCapture,
                sandboxPromptTraceStore,
                sandboxDecisionTraceStore,
                sandboxDecisionEnforcementStore,
                zeroTrustActionRepository,
                sandboxPromptUserProvisioner,
                sandboxVectorStoreIsolationSupport);
    }

    protected List<SandboxDecisionBenchmarkRunResult> executeMetric(SandboxDecisionMetric metric) {
        List<SandboxDecisionBenchmarkRunResult> runResults = executeReplayBatch();
        new SandboxDecisionMetricReportWriter(objectMapper, REPORT_DIRECTORY).write(metric, runResults);
        return runResults;
    }

    protected List<SandboxDecisionBenchmarkRunResult> executeOfficialSuite() {
        List<SandboxDecisionBenchmarkRunResult> runResults = executeReplayBatch();
        SandboxDecisionMetricReportWriter metricReportWriter =
                new SandboxDecisionMetricReportWriter(objectMapper, REPORT_DIRECTORY);
        metricReportWriter.writeAll(runResults);
        new SandboxDecisionAggregateReportWriter(objectMapper, REPORT_DIRECTORY).write(runResults);
        return runResults;
    }

    protected List<SandboxDecisionBenchmarkRunResult> executeReplayBatch() {
        SandboxDecisionBenchmarkBatchRunner batchRunner =
                new SandboxDecisionBenchmarkBatchRunner(
                        replayHarness,
                        objectMapper,
                        sandboxPromptTruthRealLlmDecisionReplayExecutor);
        return batchRunner.execute(
                SandboxPromptReplayScenarioCatalog.resolve(SandboxDecisionBenchmarkSettings.scenarioSelector()),
                SandboxDecisionBenchmarkSettings.sampleCount(),
                SandboxDecisionBenchmarkSettings.roundCount(),
                DEFAULT_PASSWORD);
    }

    @AfterAll
    static void tearDownRealLlmBenchmark() {
        SandboxVectorStoreIsolationSupport.cleanupReplayArtifactsInDatabase();
        POSTGRESQL_SCHEMA_SUPPORT.dropQuietly();
    }
}
