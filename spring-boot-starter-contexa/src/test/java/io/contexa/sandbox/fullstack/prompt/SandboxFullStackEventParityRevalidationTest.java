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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 브라우저 패리티 재검증용 full-stack 테스트.
 *
 * 목적:
 * - 실제 WebClient + 실제 MFA + 실제 보호 리소스 호출 경로를 그대로 탄다.
 * - 첫 보호 리소스 요청에서 isNewUser / isNewSession / isNewDevice가
 *   "테스트 페이지 / MFA 보조 요청"에 의해 먼저 소모되지 않는지 확인한다.
 * - 결과를 별도 JSON 보고서로 남겨 브라우저 truth와 직접 비교할 수 있게 한다.
 */
@SpringBootTest(
        classes = SpringBootStarterContexaApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({
        SandboxPromptTraceTestConfiguration.class,
        SandboxOttCaptureTestConfiguration.class,
        SandboxPromptSeedTestConfiguration.class
})
class SandboxFullStackEventParityRevalidationTest {

    private static final String DEFAULT_USERNAME = System.getProperty(
            "sandbox.prompt.parity.username",
            "admin@example.com");
    private static final String DEFAULT_PASSWORD = System.getProperty(
            "sandbox.prompt.parity.password",
            "1234");
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
        registry.add("sandbox.prompt.username", () -> DEFAULT_USERNAME);
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
    @DisplayName("브라우저 패리티 재검증: 첫 보호 리소스 접근의 신규성 플래그는 보조 요청이 아니라 컨텍스트 기준으로 계산되어야 한다")
    void shouldKeepNewnessFlagsForFirstPromptRelevantAccess() throws IOException {
        // Given:
        // - 브라우저와 같은 HTTP/MFA 경로를 탄다.
        // - 비교 대상 사용자는 실제 앱에 이미 존재하는 admin 계정(default: admin@example.com)이다.
        // - 테스트 페이지 진입, MFA 화면, status probe 같은 보조 요청은 prompt-relevant가 아니므로
        //   isNewUser / isNewSession / isNewDevice를 먼저 소모하면 안 된다.
        SandboxPromptReplayRun replayRun = replayHarness.replayThreeRounds(
                DEFAULT_USERNAME,
                DEFAULT_PASSWORD,
                "browser-parity-revalidation");

        SandboxPromptReplayRound firstRound = replayRun.firstRound();
        SandboxPromptReplayRound secondRound = replayRun.secondRound();
        SandboxPromptReplayRound thirdRound = replayRun.thirdRound();

        Map<String, Object> firstMetadata = firstRound.snapshot().event().getMetadata();
        Map<String, Object> secondMetadata = secondRound.snapshot().event().getMetadata();
        Map<String, Object> thirdMetadata = thirdRound.snapshot().event().getMetadata();

        // When:
        // - 1차는 "첫 prompt-relevant 보호 리소스 접근"이다.
        // - 2차/3차는 같은 사용자가 같은 세션 흐름에서 재진입한 후속 회차다.
        //
        // Then:
        // - 1차 신규성 플래그는 true 여야 한다.
        // - 2차/3차 신규성 플래그는 false 여야 한다.
        // - 이 결과는 테스트 페이지/status/MFA 요청이 신규성을 먼저 잡아먹지 않는다는 것을 의미한다.
        assertThat(Boolean.TRUE.equals(firstMetadata.get("isNewUser")))
                .as("첫 보호 리소스 접근은 prompt-relevant 기준 최초 사용자 관측이므로 isNewUser=true 여야 한다.")
                .isTrue();
        assertThat(Boolean.TRUE.equals(firstMetadata.get("isNewSession")))
                .as("첫 보호 리소스 접근은 prompt-relevant 기준 최초 세션 관측이므로 isNewSession=true 여야 한다.")
                .isTrue();
        assertThat(Boolean.TRUE.equals(firstMetadata.get("isNewDevice")))
                .as("첫 보호 리소스 접근은 prompt-relevant 기준 최초 userAgent 관측이므로 isNewDevice=true 여야 한다.")
                .isTrue();

        assertThat(Boolean.TRUE.equals(secondMetadata.get("isNewUser")))
                .as("같은 사용자의 2차 보호 리소스 접근은 이미 1차에서 등록됐으므로 isNewUser=false 여야 한다.")
                .isFalse();
        assertThat(Boolean.TRUE.equals(secondMetadata.get("isNewSession")))
                .as("같은 세션의 2차 보호 리소스 접근은 신규 세션이 아니므로 isNewSession=false 여야 한다.")
                .isFalse();
        assertThat(Boolean.TRUE.equals(secondMetadata.get("isNewDevice")))
                .as("같은 userAgent의 2차 보호 리소스 접근은 신규 device가 아니므로 isNewDevice=false 여야 한다.")
                .isFalse();

        assertThat(Boolean.TRUE.equals(thirdMetadata.get("isNewUser"))).isFalse();
        assertThat(Boolean.TRUE.equals(thirdMetadata.get("isNewSession"))).isFalse();
        assertThat(Boolean.TRUE.equals(thirdMetadata.get("isNewDevice"))).isFalse();

        assertThat(firstMetadata.get("authorizationEffect"))
                .as("브라우저 truth와 동일하게 첫 회차 authorizationEffect는 UNKNOWN이 아니라 ALLOW/DENY 같은 명시값이어야 한다.")
                .isEqualTo("ALLOW");
        assertThat(firstMetadata.get("mfaVerified"))
                .as("실제 OTT MFA를 통과했으므로 첫 회차 mfaVerified=true 여야 한다.")
                .isEqualTo(true);
        assertThat(firstMetadata.get("requestPath"))
                .as("첫 회차 requestPath는 실제 보호 리소스 경로와 같아야 한다.")
                .isEqualTo("/admin/api/security-test/sensitive/resource-001");

        writeParityReport(replayRun);
    }

    private void writeParityReport(SandboxPromptReplayRun replayRun) throws IOException {
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("username", DEFAULT_USERNAME);
        report.put("scenarioKey", replayRun.scenarioKey());
        report.put("roundCount", replayRun.rounds().size());
        report.put("rounds", replayRun.rounds().stream()
                .map(round -> {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("phase", round.phase());
                    entry.put("requestId", round.requestId());
                    entry.put("requestPath", round.requestPath());
                    entry.put("response", round.responseBody());
                    entry.put("trace", round.snapshot().toDiagnosticMap(objectMapper));
                    return entry;
                })
                .toList());

        Path reportDirectory = Path.of("build", "reports", "sandbox-fullstack-parity");
        Files.createDirectories(reportDirectory);
        Files.writeString(
                reportDirectory.resolve("event-parity-revalidation.json"),
                objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(report));
    }
}
