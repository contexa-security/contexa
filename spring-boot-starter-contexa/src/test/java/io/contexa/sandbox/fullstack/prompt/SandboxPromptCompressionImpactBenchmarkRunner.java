package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class SandboxPromptCompressionImpactBenchmarkRunner {

    private final ObjectMapper objectMapper;
    private final SandboxDecisionBenchmarkBatchRunner decisionBatchRunner;
    private final Path reportDirectory;

    public SandboxPromptCompressionImpactBenchmarkRunner(
            ObjectMapper objectMapper,
            SandboxDecisionBenchmarkBatchRunner decisionBatchRunner,
            Path reportDirectory) {
        this.objectMapper = objectMapper;
        this.decisionBatchRunner = decisionBatchRunner;
        this.reportDirectory = reportDirectory;
    }

    public SandboxPromptCompressionImpactBenchmarkResult execute(
            List<SandboxPromptReplayScenario> scenarios,
            int sampleCount,
            int roundCount,
            String password) throws IOException {
        Files.createDirectories(reportDirectory);

        SandboxPromptCompressionImpactComparison baseline = executeProfile(
                SandboxPromptCompressionImpactBenchmarkSettings.baselineProfile(),
                scenarios,
                sampleCount,
                roundCount,
                password);
        SandboxPromptCompressionImpactComparison candidate = executeProfile(
                SandboxPromptCompressionImpactBenchmarkSettings.candidateProfile(),
                scenarios,
                sampleCount,
                roundCount,
                password);

        new SandboxPromptCompressionImpactReportWriter(objectMapper, reportDirectory)
                .write(SandboxPromptCompressionImpactBenchmarkSettings.comparisonId(), baseline, candidate);

        return new SandboxPromptCompressionImpactBenchmarkResult(baseline, candidate);
    }

    private SandboxPromptCompressionImpactComparison executeProfile(
            String budgetProfile,
            List<SandboxPromptReplayScenario> scenarios,
            int sampleCount,
            int roundCount,
            String password) throws IOException {
        String previousProfile = System.getProperty("sandbox.prompt.benchmark.profile");
        try {
            System.setProperty("sandbox.prompt.benchmark.profile", budgetProfile);

            List<SandboxDecisionBenchmarkRunResult> decisionRunResults = decisionBatchRunner.execute(
                    scenarios,
                    sampleCount,
                    roundCount,
                    password);
            List<SandboxPromptBenchmarkRunResult> promptRunResults = decisionRunResults.stream()
                    .map(this::toPromptRunResult)
                    .toList();

            Path profileDirectory = reportDirectory.resolve(profileDirectoryName(budgetProfile));
            Files.createDirectories(profileDirectory);
            new SandboxDecisionMetricReportWriter(objectMapper, profileDirectory).writeAll(decisionRunResults);
            new SandboxDecisionAggregateReportWriter(objectMapper, profileDirectory).write(decisionRunResults);
            new SandboxPromptCompressionEvidenceWriter(objectMapper, profileDirectory.resolve("compression"))
                    .write(promptRunResults);

            return new SandboxPromptCompressionImpactComparison(
                    budgetProfile,
                    SandboxDecisionBenchmarkSettings.scenarioSelector(),
                    roundCount,
                    promptRunResults,
                    decisionRunResults);
        } finally {
            if (previousProfile == null) {
                System.clearProperty("sandbox.prompt.benchmark.profile");
            } else {
                System.setProperty("sandbox.prompt.benchmark.profile", previousProfile);
            }
        }
    }

    private SandboxPromptBenchmarkRunResult toPromptRunResult(
            SandboxDecisionBenchmarkRunResult decisionRunResult) {
        return new SandboxPromptBenchmarkRunResult(
                decisionRunResult.benchmarkRunId(),
                decisionRunResult.username(),
                decisionRunResult.replayRun(),
                List.of(),
                null,
                List.of(),
                List.of(),
                List.of(),
                Map.of(),
                List.of());
    }

    static String profileDirectoryName(String budgetProfile) {
        return budgetProfile.toLowerCase(Locale.ROOT);
    }
}
