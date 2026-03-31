package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.ai.document.Document;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxPromptBenchmarkReportWriterTest {

    private static final OffsetDateTime BASE_TIME = OffsetDateTime.of(2026, 1, 5, 9, 0, 0, 0, ZoneOffset.ofHours(9));

    private final ObjectMapper objectMapper = new ObjectMapper();

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("report writer는 stale ledger를 덮어쓰고 scenario 및 실험군 요약을 함께 기록해야 한다")
    void shouldOverwriteStaleLedgersAndWriteScenarioSummaries() throws Exception {
        // 같은 파일명을 계속 쓰는 benchmark는 이전 실행 흔적이 남으면 즉시 통계가 오염된다.
        // 따라서 defects.ndjson 같은 ledger는 매 실행 완전히 덮어써야 하고
        // scenario/experimentGroup 요약도 같이 떨어져야 나중에 원인 구분이 가능하다.
        Path reportDir = tempDir.resolve("report");
        Files.createDirectories(reportDir);
        Files.writeString(reportDir.resolve("defects.ndjson"), "{\"stale\":true}\n");

        SandboxPromptBenchmarkReportWriter writer = new SandboxPromptBenchmarkReportWriter(objectMapper, reportDir);
        writer.writeReport("Sandbox Full-Stack Context Prompt Benchmark", List.of(
                buildRunResult(
                        "benchmark-run-1",
                        "writer-admin-001@example.com",
                        "MFA_SENSITIVE_RESOURCE_REPEAT",
                        "WEBCLIENT_FULLSTACK_CONTEXT_PROMPT",
                        97.0d,
                        96.0d,
                        List.of())));

        String defectsLedger = Files.readString(reportDir.resolve("defects.ndjson"));
        String summaryJson = Files.readString(reportDir.resolve("summary.json"));
        String scenarioLedger = Files.readString(reportDir.resolve("scenarios.ndjson"));
        String experimentLedger = Files.readString(reportDir.resolve("experiment-groups.ndjson"));

        assertThat(defectsLedger).isBlank();
        assertThat(summaryJson).contains("scenarioSummaries");
        assertThat(summaryJson).contains("experimentGroupSummaries");
        assertThat(summaryJson).contains("userProfileSummaries");
        assertThat(summaryJson).contains("scenarioFamilySummaries");
        assertThat(summaryJson).contains("officialMetricCoverage");
        assertThat(summaryJson).contains("metricCatalog");
        assertThat(summaryJson).contains("responsibilityBoundarySummary");
        assertThat(scenarioLedger).contains("MFA_SENSITIVE_RESOURCE_REPEAT");
        assertThat(experimentLedger).contains("WEBCLIENT_FULLSTACK_CONTEXT_PROMPT");
    }

    @Test
    @DisplayName("report writer는 이전 실행 대비 metric drift를 계산해야 한다")
    void shouldComputeMetricDriftAgainstPreviousRun() throws Exception {
        // 공식 benchmark는 이번 실행만 좋아 보이는지, 직전 대비 실제로 개선됐는지를 같이 보여줘야 한다.
        Path reportDir = tempDir.resolve("drift-report");
        SandboxPromptBenchmarkReportWriter writer = new SandboxPromptBenchmarkReportWriter(objectMapper, reportDir);

        writer.writeReport("Sandbox Full-Stack Context Prompt Benchmark", List.of(
                buildRunResult(
                        "benchmark-run-1",
                        "writer-admin-002@example.com",
                        "MFA_NORMAL_RESOURCE_REPEAT",
                        "WEBCLIENT_FULLSTACK_STABILITY",
                        96.0d,
                        95.0d,
                        List.of())));

        writer.writeReport("Sandbox Full-Stack Context Prompt Benchmark", List.of(
                buildRunResult(
                        "benchmark-run-2",
                        "writer-admin-003@example.com",
                        "MFA_NORMAL_RESOURCE_REPEAT",
                        "WEBCLIENT_FULLSTACK_STABILITY",
                        99.0d,
                        98.0d,
                        List.of())));

        @SuppressWarnings("unchecked")
        Map<String, Object> summary = objectMapper.readValue(Files.readString(reportDir.resolve("summary.json")), Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> drift = (Map<String, Object>) summary.get("metricDriftFromPreviousRun");

        assertThat(drift.get("previousRunAvailable")).isEqualTo(Boolean.TRUE);
        assertThat(((Number) drift.get("improvedMetricCount")).intValue()).isGreaterThan(0);
    }

    private SandboxPromptBenchmarkRunResult buildRunResult(
            String benchmarkRunId,
            String username,
            String scenarioKey,
            String experimentGroup,
            double contextCompletenessRate,
            double progressionRate,
            List<SandboxPromptDefectFinding> defectFindings) {

        SandboxPromptReplayScenario scenario = new SandboxPromptReplayScenario(
                scenarioKey,
                experimentGroup,
                "NORMAL_USER",
                "Prompt should stay stable across rounds",
                "ADMIN_NORMAL_BASELINE_STABILITY",
                "STABILITY",
                List.of(
                        new SandboxPromptRoundPlan(
                                "R1",
                                "/admin/api/security-test/normal/resource-001",
                                SandboxFullStackPromptReplayHarness.DEFAULT_CLIENT_IP,
                                SandboxFullStackPromptReplayHarness.DEFAULT_BROWSER_USER_AGENT,
                                "Chrome 120 / Windows 11",
                                "corp-laptop-a",
                                BASE_TIME,
                                SandboxPromptSessionMode.NEW_SESSION,
                                6200L,
                                "BASELINE",
                                "NONE",
                                "baseline round",
                                List.of("EXPECT_HISTORY_BUILDUP")),
                        new SandboxPromptRoundPlan(
                                "R2",
                                "/admin/api/security-test/normal/resource-001",
                                SandboxFullStackPromptReplayHarness.DEFAULT_CLIENT_IP,
                                SandboxFullStackPromptReplayHarness.DEFAULT_BROWSER_USER_AGENT,
                                "Chrome 120 / Windows 11",
                                "corp-laptop-a",
                                BASE_TIME.plusMinutes(12),
                                SandboxPromptSessionMode.REUSE_SESSION,
                                6200L,
                                "BASELINE",
                                "NONE",
                                "baseline round",
                                List.of("EXPECT_HISTORY_BUILDUP")),
                        new SandboxPromptRoundPlan(
                                "R3",
                                "/admin/api/security-test/sensitive/resource-001",
                                SandboxFullStackPromptReplayHarness.DEFAULT_CLIENT_IP,
                                SandboxFullStackPromptReplayHarness.DEFAULT_BROWSER_USER_AGENT,
                                "Chrome 120 / Windows 11",
                                "corp-laptop-a",
                                BASE_TIME.plusDays(7),
                                SandboxPromptSessionMode.NEW_SESSION,
                                6200L,
                                "ANOMALY",
                                "RESOURCE_SENSITIVITY_SURGE",
                                "sensitivity surge",
                                List.of("EXPECT_HISTORY_CONTRAST"))));

        SandboxPromptTraceSnapshot firstSnapshot = snapshot("request-1", 0);
        SandboxPromptTraceSnapshot secondSnapshot = snapshot("request-2", 1);
        SandboxPromptTraceSnapshot thirdSnapshot = snapshot("request-3", 2);

        SandboxPromptReplayRun replayRun = new SandboxPromptReplayRun(
                benchmarkRunId,
                username,
                scenarioKey,
                experimentGroup,
                scenario,
                List.of(
                        new SandboxPromptReplayRound("INITIAL", 1, scenario.roundPlanForRound(1), "request-1", scenario.requestPathForRound(1), scenario.clientIpForRound(1), scenario.simulatedUserAgentLabelForRound(1), "device-1", Map.of("demoPhase", "INITIAL"), firstSnapshot),
                        new SandboxPromptReplayRound("FOLLOW_UP", 2, scenario.roundPlanForRound(2), "request-2", scenario.requestPathForRound(2), scenario.clientIpForRound(2), scenario.simulatedUserAgentLabelForRound(2), "device-1", Map.of("demoPhase", "FOLLOW_UP"), secondSnapshot),
                        new SandboxPromptReplayRound("FOLLOW_UP", 3, scenario.roundPlanForRound(3), "request-3", scenario.requestPathForRound(3), scenario.clientIpForRound(3), scenario.simulatedUserAgentLabelForRound(3), "device-1", Map.of("demoPhase", "FOLLOW_UP"), thirdSnapshot)));

        List<SandboxPromptQualityScorecard> roundScorecards = List.of(
                SandboxPromptQualityScorecard.of("1차", List.of(new SandboxPromptQualityScorecard.CheckResult("ok", true, "ok"))),
                SandboxPromptQualityScorecard.of("2차", List.of(new SandboxPromptQualityScorecard.CheckResult("ok", true, "ok"))),
                SandboxPromptQualityScorecard.of("3차", List.of(new SandboxPromptQualityScorecard.CheckResult("ok", true, "ok"))));

        SandboxPromptQualityScorecard progressionScorecard = SandboxPromptQualityScorecard.of(
                "progression",
                List.of(new SandboxPromptQualityScorecard.CheckResult("ok", true, "ok")));

        Map<String, Double> metrics = new LinkedHashMap<>();
        metrics.put("Context Completeness Rate", contextCompletenessRate);
        metrics.put("Progression Score", progressionRate);
        metrics.put("Round Progression Integrity", progressionRate);

        return new SandboxPromptBenchmarkRunResult(
                benchmarkRunId,
                username,
                replayRun,
                roundScorecards,
                progressionScorecard,
                List.of(
                        new SandboxPromptTraceContractAssessment("1차 trace", 100.0d, List.of()),
                        new SandboxPromptTraceContractAssessment("2차 trace", 100.0d, List.of()),
                        new SandboxPromptTraceContractAssessment("3차 trace", 100.0d, List.of())),
                List.of(
                        new SandboxPromptFidelityAssessment("1차 fidelity", 100.0d, List.of("SYSTEM_INSTRUCTION"), List.of("SYSTEM_INSTRUCTION"), List.of(), 0, List.of()),
                        new SandboxPromptFidelityAssessment("2차 fidelity", 100.0d, List.of("SYSTEM_INSTRUCTION"), List.of("SYSTEM_INSTRUCTION"), List.of(), 0, List.of()),
                        new SandboxPromptFidelityAssessment("3차 fidelity", 100.0d, List.of("SYSTEM_INSTRUCTION"), List.of("SYSTEM_INSTRUCTION"), List.of(), 0, List.of())),
                List.of(
                        new SandboxPromptArtifactIntegrityAssessment(100.0d, List.of()),
                        new SandboxPromptArtifactIntegrityAssessment(100.0d, List.of()),
                        new SandboxPromptArtifactIntegrityAssessment(100.0d, List.of())),
                metrics,
                defectFindings);
    }

    private SandboxPromptTraceSnapshot snapshot(String requestId, int relatedDocumentCount) {
        List<Document> relatedDocuments = java.util.stream.IntStream.range(0, relatedDocumentCount)
                .mapToObj(index -> new Document("related-doc-" + index, Map.of(
                        "requestPath", "/admin/api/security-test/normal/resource-001",
                        "userId", "writer-admin@example.com",
                        "retrievalPurpose", "security_investigation")))
                .toList();

        return new SandboxPromptTraceSnapshot(
                requestId,
                Instant.now(),
                null,
                null,
                null,
                relatedDocuments,
                null,
                "You are a Zero Trust security analyst AI.\n=== DECISION ===\n<output_format>\n\"action\":\"ALLOW|CHALLENGE|BLOCK|ESCALATE\"",
                "=== CURRENT REQUEST AND EVENT ===\nRequestPath: /admin/api/security-test/normal/resource-001\nMfaVerified: true\nAuthorizationEffect: ALLOW\n=== OBSERVED WORK PATTERN CONTEXT ===\nWorkProfileSummary: Window 7d | Observations " + Math.max(1, relatedDocumentCount) + "\n",
                new LinkedHashMap<>(Map.of(
                        "promptVersion", "2026.03.26-e0.1",
                        "contractVersion", "CORTEX_PROMPT_CONTRACT_V2",
                        "templateKey", "SecurityDecisionStandard",
                        "promptSectionSet", List.of("SYSTEM_INSTRUCTION"),
                        "omittedSections", List.of())),
                null);
    }
}
