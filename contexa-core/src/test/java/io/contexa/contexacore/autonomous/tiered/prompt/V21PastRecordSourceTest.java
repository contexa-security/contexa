/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.verification.evidence.SealedPastRecordSummary;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * BR-C6 (bundle v21.19, QF-13 and QF-14): a v21 past record line states how its record was learned and, when a record has
 * arguments that came from a tool's output, names them; both fields stand before the authorization. The v19 and v20
 * lines are the twelve fields they were, the sealed package keeps the two metadata keys, and the inspector compares
 * every v21 line with the sealed records.
 */
class V21PastRecordSourceTest {

    private static final PromptInspector INSPECTOR = new PromptInspector(PromptInspector.coreChecks(),
            InspectionGolden.JSON);
    private static final List<String> SOURCES = List.of("MODEL_ALLOW", "VERIFIED", "PROMOTED", "ADMIN_RELEASE");
    private static final PromptDictionaryEntry PAST_RECORD = entry("PastRecord{i}");
    private static final PromptDictionaryEntry NEW_PAST_RECORD = entry("NewPastRecord{i}");

    private static PromptDictionaryEntry entry(String name) {
        return SecurityDecisionPromptDictionary.V21_ENTRIES.stream().filter(candidate -> candidate.name().equals(name))
                .findFirst().orElseThrow();
    }

    @Test
    void aV21RecordOfNoStatedSourceIsSaidNotToHaveOneAndTheV20LineStaysTheTwelveFields() {
        JsonNode goldenCase = firstWithPastRecords();

        InspectionGolden.Render v21 = render(goldenCase, SecurityDecisionPromptBundles.V21);
        InspectionGolden.Render v20 = render(goldenCase, SecurityDecisionPromptBundles.V20);

        List<String> lines = recordLines(v21.userPrompt(), "PastRecord");
        assertThat(lines).isNotEmpty().allSatisfy(line -> assertThat(line)
                .satisfiesAnyOf(value -> assertThat(value).contains(" / learned: source not recorded / authorized as "),
                        value -> assertThat(value).matches(".*PastRecord\\d+: \\+\\d+ more")));
        assertThat(lines).filteredOn(line -> !line.contains("more")).allSatisfy(line ->
                assertThat(PAST_RECORD.acceptsValue(value(line))).as(line).isTrue());
        assertThat(recordLines(v20.userPrompt(), "PastRecord")).allSatisfy(line -> assertThat(line)
                .doesNotContain("learned:").doesNotContain("args from tool output"));
    }

    @Test
    void aV21RecordStatesTheSourceAndTheArgumentsFromAToolsOutputItWasStoredWith() {
        JsonNode goldenCase = firstWithPastRecords();
        JsonNode original = goldenCase;
        JsonNode stated = withSources(goldenCase);

        InspectionGolden.Render v21 = render(stated, SecurityDecisionPromptBundles.V21);
        InspectionGolden.Render v20 = render(stated, SecurityDecisionPromptBundles.V20);

        List<String> lines = recordLines(v21.userPrompt(), "PastRecord");
        writeExample(lines, recordLines(renderSecondPass(stated, SecurityDecisionPromptBundles.V21), "NewPastRecord"));
        String joined = String.join("\n", lines);
        assertThat(joined).contains(" / learned: by the model alone / ").contains(" / learned: after verification / ")
                .contains(" / learned: after promotion / ").contains(" / learned: by administrator release / ")
                .contains(" / args from tool output: iban, recipient / authorized as ");
        assertThat(lines).filteredOn(line -> !line.contains("more")).allSatisfy(line ->
                assertThat(PAST_RECORD.acceptsValue(value(line))).as(line).isTrue());
        // The v20 prompt of the same records is the v20 prompt of the records without the two keys, byte for byte.
        assertThat(v20.userPrompt()).isEqualTo(render(original, SecurityDecisionPromptBundles.V20).userPrompt());
    }

    @Test
    void theSecondPassOfAV21PromptDrawsTheSameFields() {
        JsonNode stated = withSources(firstWithPastRecords());

        String secondPass = renderSecondPass(stated, SecurityDecisionPromptBundles.V21);

        List<String> lines = recordLines(secondPass, "NewPastRecord");
        assertThat(lines).isNotEmpty().filteredOn(line -> !line.contains("more")).allSatisfy(line -> {
            assertThat(line).contains(" / target not shown / ").containsPattern(" / learned: [a-z ]+ / ")
                    .doesNotContain("source not recorded");
            assertThat(NEW_PAST_RECORD.acceptsValue(value(line))).as(line).isTrue();
        });
    }

    @Test
    void theInspectorFindsTheLinesAsTheSealedRecordsDrawThem() {
        JsonNode stated = withSources(firstWithPastRecords());
        InspectionGolden.Render v21 = render(stated, SecurityDecisionPromptBundles.V21);

        PromptInspectionResult result = INSPECTOR.inspect(v21.sealed());

        assertThat(result.findings()).filteredOn(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                .extracting(PromptInspectionFinding::entry).isEmpty();
    }

    /** The sealed package keeps the two keys of a record, so that the inspector reads back the record the render read. */
    @Test
    void theSealedSummaryOfARecordKeepsTheTwoKeysAndNothingMore() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("documentType", "behavior");
        metadata.put("actionFamily", "EXPORT");
        metadata.put("learnedBy", "VERIFIED");
        metadata.put("argSources", Map.of("recipient", "TOOL_OUTPUT"));
        metadata.put("argumentOrigins", "never stored on a record");
        Document record = new Document("doc-1", "text", metadata);

        Map<String, Object> summary = SealedPastRecordSummary.of(record);
        Document readBack = SealedPastRecordSummary.records(
                InspectionGolden.JSON.valueToTree(Map.of("relatedDocuments", List.of(summary))).toString()).get(0);

        assertThat(summary).containsEntry("learnedBy", "VERIFIED").containsEntry("argSources",
                Map.of("recipient", "TOOL_OUTPUT")).doesNotContainKey("argumentOrigins");
        assertThat(readBack.getMetadata()).containsEntry("learnedBy", "VERIFIED")
                .containsEntry("argSources", Map.of("recipient", "TOOL_OUTPUT"));
        assertThat(SealedPastRecordSummary.of(new Document("doc-2", "text", Map.of("actionFamily", "EXPORT"))))
                .doesNotContainKeys("learnedBy", "argSources");
    }

    @Test
    void theInspectorPointsAtALearnedFieldTheSealedRecordsDoNotHold() {
        JsonNode stated = withSources(firstWithPastRecords());
        InspectionGolden.Render v21 = render(stated, SecurityDecisionPromptBundles.V21);
        String drawn = recordLines(v21.userPrompt(), "PastRecord").stream()
                .filter(line -> line.contains("learned: after verification")).findFirst().orElseThrow();
        String forged = drawn.replace("learned: after verification", "learned: by the model alone");
        InspectionGolden.Render tampered = new InspectionGolden.Render(v21.caseKey(), v21.profile(), v21.systemPrompt(),
                v21.userPrompt().replace(drawn, forged), v21.used(), v21.executionMetadata(), v21.ragResultsJson(),
                v21.requestFactsJson());

        PromptInspectionResult result = INSPECTOR.inspect(tampered.sealed());

        assertThat(result.findings()).filteredOn(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                .anyMatch(finding -> finding.actual() != null && finding.actual().contains("learned: by the model alone"));
    }

    @Test
    void theInspectorPointsAtAV21LineWithoutItsLearnedField() {
        InspectionGolden.Render v21 = render(firstWithPastRecords(), SecurityDecisionPromptBundles.V21);
        String drawn = recordLines(v21.userPrompt(), "PastRecord").stream().filter(line -> !line.contains("more"))
                .findFirst().orElseThrow();
        String cut = drawn.replace(" / learned: source not recorded", "");
        InspectionGolden.Render tampered = new InspectionGolden.Render(v21.caseKey(), v21.profile(), v21.systemPrompt(),
                v21.userPrompt().replace(drawn, cut), v21.used(), v21.executionMetadata(), v21.ragResultsJson(),
                v21.requestFactsJson());

        PromptInspectionResult result = INSPECTOR.inspect(tampered.sealed());

        assertThat(result.findings()).filteredOn(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                .isNotEmpty();
    }

    // ---- the golden case with past records, with the two keys the store paths write

    /** The golden case with the most past records (the four sources need four of them). */
    private static JsonNode firstWithPastRecords() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        JsonNode most = null;
        for (JsonNode goldenCase : golden.cases()) {
            if (most == null || goldenCase.path("ragResults").path("relatedDocuments").size()
                    > most.path("ragResults").path("relatedDocuments").size()) {
                most = goldenCase;
            }
        }
        InspectionGolden.Render v21 = render(most, SecurityDecisionPromptBundles.V21);
        assertThat(recordLines(v21.userPrompt(), "PastRecord")).as("the golden case with most past records").isNotEmpty();
        assertThat(most.path("ragResults").path("relatedDocuments").size()).isGreaterThanOrEqualTo(4);
        return most;
    }

    /** The case with its past records stored by the four paths in turn, and the arguments of two of them classified. */
    private static JsonNode withSources(JsonNode goldenCase) {
        ObjectNode changed = goldenCase.deepCopy();
        ArrayNode documents = (ArrayNode) changed.path("ragResults").path("relatedDocuments");
        for (int index = 0; index < documents.size(); index++) {
            ObjectNode summary = (ObjectNode) documents.get(index);
            summary.put("learnedBy", SOURCES.get(index % SOURCES.size()));
            if (index % 2 == 0) {
                summary.set("argSources", InspectionGolden.JSON.valueToTree(Map.of("recipient", "TOOL_OUTPUT",
                        "iban", "TOOL_OUTPUT", "amount", "USER_REQUEST")));
            }
        }
        return changed;
    }

    private static InspectionGolden.Render render(JsonNode goldenCase, SecurityDecisionPromptBundles.Bundle bundle) {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(bundle.version());
        SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(goldenCase,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties);
        return new InspectionGolden.Render(rendered.caseKey(), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT,
                rendered.systemText(), rendered.userText(), rendered.canonicalContext(),
                rendered.executionMetadata().toMetadataMap(), goldenCase.path("ragResults").toString(),
                goldenCase.path("requestFacts").toString());
    }

    /** The lines of the example, kept under build/reports so that what the model gets can be read as it was drawn. */
    private static void writeExample(List<String> firstPass, List<String> secondPass) {
        try {
            Path path = Path.of("build/reports/past-record-source/v21-past-record-lines.txt");
            Files.createDirectories(path.getParent());
            Files.writeString(path, String.join("\n", firstPass) + "\n\n" + String.join("\n", secondPass) + "\n");
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    private static String renderSecondPass(JsonNode goldenCase, SecurityDecisionPromptBundles.Bundle bundle) {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(bundle.version());
        String first = golden.render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties).userText();
        return golden.render(goldenCase, PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT, properties, null,
                Map.of("layer2FirstPassUserPrompt", first, "layer2FirstPassVerdict", "ESCALATE",
                        "layer2FirstPassPastRecordsState", "TIMEOUT")).userText();
    }

    private static List<String> recordLines(String userPrompt, String label) {
        return Arrays.stream(userPrompt.split("\n"))
                .filter(line -> line.matches("(\\[[A-Z]\\d+\\] )?" + label + "\\d+: .*")).toList();
    }

    /** A line's value: what follows its label. */
    private static String value(String line) {
        return line.substring(line.indexOf(": ") + 2);
    }
}
