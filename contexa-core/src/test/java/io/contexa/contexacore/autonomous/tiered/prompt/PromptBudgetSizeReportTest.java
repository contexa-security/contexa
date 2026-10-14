package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptTokenEstimate;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TO-5 (plan 5.3.2): the sizes the budget profiles are set against. For every golden case and budget profile, the token
 * estimate of the v19 and the v20 bundle's prompt as the model gets it (counted for the showcase model), with the profile's
 * budget and whether the prompt is over it, and the v20 bundle's Layer2 second passes, reported to
 * build/reports/prompt-bundle/budget-sizes.json.
 */
class PromptBudgetSizeReportTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final Map<String, String> MODEL = Map.of("runtimeModelId", "gpt-5-nano");

    /**
     * TO-5: the budget profiles fit the v20 prompts as the model gets them, first passes in L1 and L2 and Layer2 second
     * passes in L2, so the observed budget is over only for a prompt larger than the golden ones.
     */
    @Test
    void theV20GoldenRendersFitTheirBudgets() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
        List<String> over = new ArrayList<>();
        for (JsonNode goldenCase : golden.cases()) {
            String where = goldenCase.path("caseKey").asText();
            for (PromptBudgetProfile profile : SecurityDecisionGoldenRender.PROFILES) {
                if (golden.render(goldenCase, profile, properties, null, MODEL).executionMetadata().promptTokenEstimate()
                        .budgetExceeded()) {
                    over.add(where + " " + profile);
                }
            }
            if (goldenCase.path("ragResults").path("relatedDocuments").isEmpty()) {
                continue;
            }
            Map<String, String> parameters = new LinkedHashMap<>(MODEL);
            parameters.put("layer2FirstPassUserPrompt", golden.render(goldenCase,
                    PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties, null, MODEL).userText());
            parameters.put("layer2FirstPassVerdict", "ESCALATE");
            parameters.put("layer2FirstPassPastRecordsState", "TIMEOUT");
            if (golden.render(goldenCase, PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT, properties, null, parameters)
                    .executionMetadata().promptTokenEstimate().budgetExceeded()) {
                over.add(where + " second pass");
            }
        }
        assertThat(over).isEmpty();
        // Trimming takes facts out, so the budget is observed unless a deployment turns enforcement on (TO-5).
        assertThat(new TieredStrategyProperties().getPromptRuntime().getBudgetEnforcement())
                .isEqualTo(TieredStrategyProperties.PromptRuntime.BudgetEnforcement.OBSERVE_ONLY);
    }

    @Test
    void theBudgetSizesOfTheGoldenRendersAreReported() throws IOException {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        Map<String, Object> report = new LinkedHashMap<>();
        for (SecurityDecisionPromptBundles.Bundle bundle : SecurityDecisionPromptBundles.ALL) {
            TieredStrategyProperties properties = new TieredStrategyProperties();
            properties.getPromptBundle().setActive(bundle.version());
            Map<String, Object> perProfile = new LinkedHashMap<>();
            for (PromptBudgetProfile profile : SecurityDecisionGoldenRender.PROFILES) {
                List<Map<String, Object>> rows = new ArrayList<>();
                for (JsonNode goldenCase : golden.cases()) {
                    PromptTokenEstimate estimate = golden.render(goldenCase, profile, properties, null, MODEL)
                            .executionMetadata().promptTokenEstimate();
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("case", goldenCase.path("caseKey").asText());
                    row.put("system", estimate.estimatedSystemTokens());
                    row.put("user", estimate.estimatedUserTokens());
                    row.put("total", estimate.estimatedTotalTokens());
                    row.put("overBudget", estimate.budgetExceeded());
                    rows.add(row);
                }
                List<Integer> totals = rows.stream().map(row -> (Integer) row.get("total")).sorted().toList();
                Map<String, Object> summary = new LinkedHashMap<>();
                summary.put("budget", profile.maxInputTokens());
                summary.put("min", totals.get(0));
                summary.put("median", totals.get(totals.size() / 2));
                summary.put("max", totals.get(totals.size() - 1));
                summary.put("overBudget", rows.stream().filter(row -> (Boolean) row.get("overBudget")).count());
                summary.put("cases", rows);
                perProfile.put(profile.name(), summary);
                assertThat(totals).hasSize(golden.cases().size()).allMatch(total -> total > 0);
            }
            if (bundle.layout() == SecurityDecisionPromptBundles.UserPromptLayout.V20_BLOCKS) {
                // The Layer2 second pass over a first prompt whose past records were not retrieved (W3-9).
                List<Integer> totals = new ArrayList<>();
                for (JsonNode goldenCase : golden.cases()) {
                    if (goldenCase.path("ragResults").path("relatedDocuments").isEmpty()) {
                        continue;
                    }
                    String first = golden.render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties,
                            null, MODEL).userText();
                    Map<String, String> parameters = new LinkedHashMap<>(MODEL);
                    parameters.put("layer2FirstPassUserPrompt", first);
                    parameters.put("layer2FirstPassVerdict", "ESCALATE");
                    parameters.put("layer2FirstPassPastRecordsState", "TIMEOUT");
                    totals.add(golden.render(goldenCase, PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT, properties, null,
                            parameters).executionMetadata().promptTokenEstimate().estimatedTotalTokens());
                }
                List<Integer> sorted = totals.stream().sorted().toList();
                Map<String, Object> summary = new LinkedHashMap<>();
                summary.put("budget", PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT.maxInputTokens());
                summary.put("min", sorted.get(0));
                summary.put("median", sorted.get(sorted.size() / 2));
                summary.put("max", sorted.get(sorted.size() - 1));
                summary.put("passes", sorted.size());
                perProfile.put("SECOND_PASS", summary);
            }
            report.put(bundle.version(), perProfile);
        }
        Path path = Path.of("build/reports/prompt-bundle/budget-sizes.json");
        Files.createDirectories(path.getParent());
        Files.writeString(path, JSON.writeValueAsString(report));
        assertThat(report).hasSize(SecurityDecisionPromptBundles.ALL.size());
    }
}
