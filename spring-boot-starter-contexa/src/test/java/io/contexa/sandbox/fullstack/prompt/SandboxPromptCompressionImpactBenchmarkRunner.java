package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.LinkedHashMap;
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

        Map<String, SandboxPromptCompressionImpactComparison> comparisonsByProfile = new LinkedHashMap<>();
        for (String budgetProfile : SandboxPromptCompressionImpactBenchmarkSettings.profileMatrix()) {
            comparisonsByProfile.put(
                    budgetProfile,
                    executeProfile(budgetProfile, scenarios, sampleCount, roundCount, password));
        }

        SandboxPromptCompressionImpactComparison baseline = comparisonsByProfile.get(
                SandboxPromptCompressionImpactBenchmarkSettings.baselineProfile());
        SandboxPromptCompressionImpactComparison candidate = comparisonsByProfile.get(
                SandboxPromptCompressionImpactBenchmarkSettings.candidateProfile());
        if (baseline == null || candidate == null) {
            throw new IllegalStateException("Compression impact benchmark profiles must include configured baseline and candidate");
        }

        SandboxPromptCompressionImpactReportWriter reportWriter =
                new SandboxPromptCompressionImpactReportWriter(objectMapper, reportDirectory);
        reportWriter.write(SandboxPromptCompressionImpactBenchmarkSettings.comparisonId(), baseline, candidate);
        reportWriter.writeMatrix(
                SandboxPromptCompressionImpactBenchmarkSettings.matrixId(),
                List.copyOf(comparisonsByProfile.values()),
                SandboxPromptCompressionImpactBenchmarkSettings.baselineProfile());

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
