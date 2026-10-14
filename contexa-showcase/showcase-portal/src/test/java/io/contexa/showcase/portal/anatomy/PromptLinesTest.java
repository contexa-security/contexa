package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * W3-10 of docs/showcase/프롬프트-최종-구현계획.md: a v20 prompt is cut at its block headers and counted under the
 * screen's bundles, one bundle per block. The samples in test/resources/anatomy/v20-prompts.json are the system and
 * user prompt control D stored for two real v20 decisions (2026-10-12, A3 and A3T, step 1, call 1); the expected
 * numbers were counted apart by an independent script on the same texts.
 */
class PromptLinesTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void aV20PromptIsCountedByItsBlocksInTheScreensOrder() throws IOException {
        JsonNode a3 = sample("A3");
        PromptLines lines = PromptLines.of(a3.path("systemPrompt").asText(), a3.path("userPrompt").asText());

        assertThat(lines.layout()).isEqualTo(PromptLines.V20_BLOCKS);
        assertThat(lines.system()).isEqualTo(106);
        assertThat(lines.user()).isEqualTo(51);
        assertThat(lines.total()).isEqualTo(157);
        assertThat(lines.systemPhysical()).isEqualTo(118);
        assertThat(lines.userPhysical()).isEqualTo(57);
        assertThat(lines.sections()).extracting(PromptLines.Section::name, PromptLines.Section::bundle,
                PromptLines.Section::lines).containsExactly(
                tuple("USER BASELINE", "USER_BASELINE", 16), tuple("SESSION", "SESSION", 6),
                tuple("REQUEST", "REQUEST", 10), tuple("DECISION FACTS", "DECISION_FACTS", 12),
                tuple("PAST RECORDS (scope NO_COMPARABLE_EVIDENCE)", "PAST_RECORDS", 2),
                tuple("UNKNOWN", "UNKNOWN", 3), tuple("UNTRUSTED TEXT", "UNTRUSTED_TEXT", 2));
        assertThat(lines.bundles()).as("the rules, the five parts in the order the model reads them, then the folded "
                + "ones").containsExactly(new PromptLines.Bundle("RULES", 106), new PromptLines.Bundle("REQUEST", 10),
                new PromptLines.Bundle("SESSION", 6), new PromptLines.Bundle("USER_BASELINE", 16),
                new PromptLines.Bundle("DECISION_FACTS", 12), new PromptLines.Bundle("UNKNOWN", 3),
                new PromptLines.Bundle("PAST_RECORDS", 2), new PromptLines.Bundle("UNTRUSTED_TEXT", 2),
                new PromptLines.Bundle("SECOND_PASS", 0), new PromptLines.Bundle("OTHER", 0));
        assertThat(lines.bundles().stream().mapToInt(PromptLines.Bundle::lines).sum()).isEqualTo(lines.total());
    }

    @Test
    void theQualifierOfABlockHeaderKeepsTheBlocksBundle() throws IOException {
        JsonNode a3t = sample("A3T");
        PromptLines lines = PromptLines.of(a3t.path("systemPrompt").asText(), a3t.path("userPrompt").asText());

        assertThat(lines.layout()).isEqualTo(PromptLines.V20_BLOCKS);
        assertThat(lines.total()).isEqualTo(159);
        assertThat(lines.sections()).filteredOn(section -> section.name().startsWith("PAST RECORDS"))
                .singleElement().satisfies(section -> {
                    assertThat(section.name()).isEqualTo("PAST RECORDS (scope PERSONAL_RETRIEVED_SUBSET)");
                    assertThat(section.bundle()).isEqualTo("PAST_RECORDS");
                    assertThat(section.lines()).isEqualTo(3);
                });
        assertThat(lines.bundles()).contains(new PromptLines.Bundle("DECISION_FACTS", 13),
                new PromptLines.Bundle("PAST_RECORDS", 3), new PromptLines.Bundle("OTHER", 0));
    }

    @Test
    void aSecondPassBlockIsCountedUnderItsOwnBundle() throws IOException {
        JsonNode a3 = sample("A3");
        String system = a3.path("systemPrompt").asText();
        String first = a3.path("userPrompt").asText();
        String record = sample("A3T").path("userPrompt").asText().lines()
                .filter(line -> line.startsWith("PastRecord1: ")).findFirst().orElseThrow()
                .substring("PastRecord1: ".length());
        // The core's second pass (W3-9) keeps the first prompt as it was and adds this one block after it.
        String second = first.stripTrailing() + "\n\n=== SECOND PASS (only the facts gathered after the first pass) ===\n"
                + "FirstPassVerdict: ESCALATE\n"
                + "NewlyKnown: PastRecord{i}: 1 found (first pass: not retrieved, TIMEOUT)\n"
                + "NewPastRecord1: " + record + "\n";
        PromptLines firstLines = PromptLines.of(system, first);
        PromptLines lines = PromptLines.of(system, second);

        assertThat(lines.layout()).isEqualTo(PromptLines.V20_BLOCKS);
        assertThat(lines.sections()).last().extracting(PromptLines.Section::name, PromptLines.Section::bundle,
                PromptLines.Section::lines).containsExactly("SECOND PASS (only the facts gathered after the first pass)",
                "SECOND_PASS", 4);
        assertThat(lines.bundles()).contains(new PromptLines.Bundle("SECOND_PASS", 4));
        assertThat(lines.bundles()).filteredOn(bundle -> !bundle.bundle().equals("SECOND_PASS"))
                .as("the first prompt's blocks count as they did").isEqualTo(firstLines.bundles().stream()
                        .filter(bundle -> !bundle.bundle().equals("SECOND_PASS")).toList());
    }

    @Test
    void aHeaderOfNoKnownBlockIsCountedUnderOtherAndNeverDropped() throws IOException {
        JsonNode a3 = sample("A3");
        String user = a3.path("userPrompt").asText().stripTrailing() + "\n\n=== A LATER BLOCK ===\nLine: one\n";
        PromptLines lines = PromptLines.of(a3.path("systemPrompt").asText(), user);

        assertThat(lines.layout()).isEqualTo(PromptLines.V20_BLOCKS);
        assertThat(lines.sections()).last().extracting(PromptLines.Section::bundle).isEqualTo("OTHER");
        assertThat(lines.bundles()).contains(new PromptLines.Bundle("OTHER", 2));
        assertThat(lines.bundles().stream().mapToInt(PromptLines.Bundle::lines).sum()).isEqualTo(lines.total());
    }

    @Test
    void aPromptWithoutAV20BlockKeepsTheV19Bundles() {
        PromptLines lines = PromptLines.of("rules", "=== CURRENT REQUEST AND EVENT ===\nUser is requesting x\n");

        assertThat(lines.layout()).isEqualTo(PromptLines.V19_SECTIONS);
        assertThat(lines.bundles()).extracting(PromptLines.Bundle::bundle).containsExactlyElementsOf(PromptLines.BUNDLES);
        assertThat(lines.bundles()).contains(new PromptLines.Bundle("REQUEST", 2));
    }

    private static JsonNode sample(String caseKey) throws IOException {
        try (InputStream in = PromptLinesTest.class.getResourceAsStream("/anatomy/v20-prompts.json")) {
            for (JsonNode sample : JSON.readTree(in).path("samples")) {
                if (sample.path("case").asText().equals(caseKey)) {
                    return sample;
                }
            }
        }
        throw new AssertionError("no sample " + caseKey);
    }
}
