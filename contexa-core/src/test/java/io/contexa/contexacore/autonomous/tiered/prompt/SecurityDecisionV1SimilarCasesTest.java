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
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.policy.CanonicalContextFieldPolicy;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryLine;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptEvidenceCompleteness;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * v1.0 (plan 2.3 B7, D3): a variant with the similarity search draws the similar cases apart as SimilarCase lines, and
 * every other line, count and state stays the exact lookup's, so the measurement compares the similar cases alone.
 */
class SecurityDecisionV1SimilarCasesTest {

    private static final String OTHER_TARGET_PATH = "/api/documents/ZZ-SIMILAR-9/download";

    @Test
    void theVariantsDrawTheSameUserPromptWithoutSimilarCases() {
        JsonNode a1 = goldenCase("A1");

        String similar = render(a1, SecurityDecisionPromptBundles.V1_FALLBACK_SIMILAR).userText();
        String exact = render(a1, SecurityDecisionPromptBundles.V1_FALLBACK_EXACT).userText();

        assertThat(similar).isEqualTo(exact);
        assertThat(similar).doesNotContain("SimilarCase");
    }

    @Test
    void theSimilarCasesAreDrawnApartAndEveryOtherLineStaysTheExactLookups() {
        JsonNode a1 = goldenCase("A1");
        SecurityDecisionGoldenRender.RenderedCase without = render(a1, SecurityDecisionPromptBundles.V1_FALLBACK_SIMILAR);
        SecurityDecisionGoldenRender.RenderedCase with = render(withSimilarCases(a1, 3, null),
                SecurityDecisionPromptBundles.V1_FALLBACK_SIMILAR);

        List<PromptDictionaryLine> similarLines = lines(with.userText()).stream()
                .filter(line -> line.label().startsWith("SimilarCase")).toList();
        PromptDictionaryEntry entry = SecurityDecisionPromptDictionary.V1_ENTRIES.stream()
                .filter(candidate -> candidate.block() == PromptBlock.PAST_RECORDS
                        && "SimilarCase{i}".equals(candidate.name()))
                .findFirst().orElseThrow();

        assertThat(similarLines).extracting(PromptDictionaryLine::label)
                .containsExactly("SimilarCase1", "SimilarCase2", "SimilarCase3");
        // The hypotheses may weigh a similar case: each line carries a past record fact id.
        assertThat(similarLines).allSatisfy(line -> assertThat(line.factId()).matches("\\[P\\d+\\] "));
        similarLines.forEach(line -> assertThat(Pattern.matches(entry.formatPattern(), line.value()))
                .as(line.text()).isTrue());
        // Every other line by its label and value: the fact ids after the similar cases count on, nothing else moves.
        assertThat(labelsAndValues(with.userText()).stream().filter(line -> !line.startsWith("SimilarCase")).toList())
                .containsExactlyElementsOf(labelsAndValues(without.userText()));
        assertThat(with.executionMetadata().toMetadataMap().get("relatedDocumentCount"))
                .isEqualTo(without.executionMetadata().toMetadataMap().get("relatedDocumentCount"));
    }

    @Test
    void aSimilarCaseOfAnotherTargetPutsItsTargetInTheUntrustedText() {
        JsonNode a1 = goldenCase("A1");

        String userText = render(withSimilarCases(a1, 1, OTHER_TARGET_PATH),
                SecurityDecisionPromptBundles.V1_RECORD_SIMILAR).userText();

        assertThat(userText).contains(UntrustedTextSources.SIMILAR_CASE_TARGET)
                .contains("ZZ-SIMILAR-9");
    }

    @Test
    void onlyTheSimilarCaseVariantsReadTheSimilarCases() {
        JsonNode a1 = goldenCase("A1");
        String reading = SecurityDecisionPromptSections.V1_SIMILAR_CASES_READING.strip();

        assertThat(render(a1, SecurityDecisionPromptBundles.V1_FALLBACK_SIMILAR).systemText()).contains(reading);
        assertThat(render(a1, SecurityDecisionPromptBundles.V1_RECORD_SIMILAR).systemText()).contains(reading);
        assertThat(render(a1, SecurityDecisionPromptBundles.V1_FALLBACK_EXACT).systemText()).doesNotContain(reading);
        assertThat(render(a1, SecurityDecisionPromptBundles.V1_RECORD_EXACT).systemText()).doesNotContain(reading);
    }

    /**
     * Plan 2.3 A11 (and the 1-2 condition moved to 1-5): every golden case drawn by every v1.0 variant at both budget
     * profiles keeps the v1.0 dictionary's form, by the render's own audit; a line out of its form is named.
     */
    @Test
    void everyGoldenRenderOfEveryVariantKeepsTheDictionaryForm() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        int renders = 0;
        for (SecurityDecisionPromptBundles.Bundle bundle : SecurityDecisionPromptBundles.V1_BUNDLES) {
            TieredStrategyProperties properties = new TieredStrategyProperties();
            properties.getPromptBundle().setActive(bundle.version());
            for (JsonNode goldenCase : golden.cases()) {
                for (PromptBudgetProfile profile : SecurityDecisionGoldenRender.PROFILES) {
                    Object violations = golden.render(goldenCase, profile, properties).executionMetadata()
                            .supplementalMetadata().get("promptContractViolations");
                    assertThat(violations).as(bundle.version() + " " + goldenCase.path("caseKey").asText() + " " + profile)
                            .asList().noneMatch(violation -> String.valueOf(violation).startsWith("V1_DICTIONARY_FORM"));
                    renders++;
                }
            }
        }
        SecurityPromptContractAudit broken = SecurityDecisionPromptSections.withDictionaryFormViolations(
                new SecurityPromptContractAudit(Map.of(), Map.of(), Map.of(), Map.of(), List.of()),
                "=== REQUEST ===\nNetworkZone: somewhere\n", SecurityDecisionPromptDictionary.V1_ENTRIES);

        assertThat(renders).isEqualTo(SecurityDecisionPromptBundles.V1_BUNDLES.size() * golden.cases().size()
                * SecurityDecisionGoldenRender.PROFILES.size());
        assertThat(broken.violations()).containsExactly("V1_DICTIONARY_FORM:REQUEST.NetworkZone is out of its form");
    }

    /**
     * Plan 2.3 A12: a v1.0 render reads its completeness on the UNKNOWN block and the canonical fields together, so a
     * render whose context misses a canonical field the v19 completeness reads is never sufficient.
     */
    @Test
    void aV1RenderIsNeverSufficientWithoutTheCanonicalFieldsTheCompletenessReads() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V1_FALLBACK_EXACT.version());
        int missingFields = 0;
        for (JsonNode goldenCase : golden.cases()) {
            ObjectNode changed = goldenCase.deepCopy();
            // The authorization's roles and scope taken out: a field the v19 completeness requires.
            ObjectNode context = (ObjectNode) changed.path("canonicalContext");
            context.remove("authorization");
            SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(changed,
                    PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties);
            CanonicalSecurityContext used = rendered.canonicalContext();
            if (used != null && !(CanonicalContextFieldPolicy.hasEffectiveRoles(used)
                    && CanonicalContextFieldPolicy.hasAuthorizationScope(used))) {
                missingFields++;
                assertThat(rendered.executionMetadata().promptEvidenceCompleteness())
                        .as(goldenCase.path("caseKey").asText())
                        .isNotEqualTo(PromptEvidenceCompleteness.SUFFICIENT);
            }
        }
        assertThat(missingFields).isPositive();
    }

    /** Plan 2.3 A13: a prompt that draws similar cases alone still states that past records reached it. */
    @Test
    void similarCaseLinesCountAsPastRecordsThatReachedThePrompt() {
        ObjectNode onlySimilar = withSimilarCases(goldenCase("A1"), 2, null).deepCopy();
        ArrayNode documents = (ArrayNode) onlySimilar.path("ragResults").path("relatedDocuments");
        for (int index = documents.size() - 1; index >= 0; index--) {
            if (!documents.get(index).path(SimilarCases.MARK).asBoolean()) {
                documents.remove(index);
            }
        }

        SecurityDecisionGoldenRender.RenderedCase rendered = render(onlySimilar,
                SecurityDecisionPromptBundles.V1_RECORD_SIMILAR);

        assertThat(rendered.userText()).contains("SimilarCase1: ").doesNotContainPattern("(?m)^(\\[P\\d+\\] )?PastRecord1: ");
        assertThat(rendered.executionMetadata().toMetadataMap()).containsEntry("ragProjectedToFinalPrompt", true);
    }

    @Test
    void theSimilarCasesTheExactLookupFoundAreLeftOutAndTheRestMarked() {
        Document exact = new Document("record-1", "exact", Map.of("eventId", "e1"));
        Document again = new Document("record-1", "exact again", Map.of("eventId", "e1"));
        Document similar = new Document("record-2", "similar", Map.of("eventId", "e2"));

        List<Document> joined = SimilarCases.join(List.of(exact), List.of(again, similar));

        assertThat(joined).extracting(Document::getId).containsExactly("record-1", "record-2");
        assertThat(SimilarCases.exact(joined)).containsExactly(exact);
        assertThat(SimilarCases.similar(joined)).extracting(Document::getId).containsExactly("record-2");
        assertThat(SimilarCases.isSimilarCase(similar)).as("the search's own document stays unmarked").isFalse();
    }

    /** The golden case with copies of its first records as similar cases, at another target when a path is given. */
    private static JsonNode withSimilarCases(JsonNode goldenCase, int count, String requestPath) {
        ObjectNode changed = goldenCase.deepCopy();
        ArrayNode documents = (ArrayNode) changed.path("ragResults").path("relatedDocuments");
        List<ObjectNode> copies = new ArrayList<>();
        for (int index = 0; index < count; index++) {
            ObjectNode copy = documents.get(index).deepCopy();
            copy.put("id", "similar-case-" + index);
            copy.put("eventId", "similar-event-" + index);
            copy.put(SimilarCases.MARK, true);
            if (requestPath != null) {
                copy.put("requestPath", requestPath);
            }
            copies.add(copy);
        }
        copies.forEach(documents::add);
        return changed;
    }

    private static JsonNode goldenCase(String caseKey) {
        return SecurityDecisionGoldenRender.load().cases().stream()
                .filter(item -> caseKey.equals(item.path("caseKey").asText())).findFirst().orElseThrow();
    }

    private static SecurityDecisionGoldenRender.RenderedCase render(JsonNode goldenCase,
                                                                    SecurityDecisionPromptBundles.Bundle bundle) {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(bundle.version());
        return SecurityDecisionGoldenRender.load().render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT,
                properties);
    }

    private static List<PromptDictionaryLine> lines(String userText) {
        return userText.lines().map(PromptDictionaryLine::parse).filter(Objects::nonNull).toList();
    }

    private static List<String> labelsAndValues(String userText) {
        return lines(userText).stream().map(line -> line.label() + ": " + line.value()).toList();
    }
}
