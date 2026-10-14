package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TO-4 (plan 5.3.2, W4-1 brought forward): the v20 bundle's system text is written for the v20 user prompt. It names
 * only facts the dictionary has, states each boundary once, follows the blocks in its decision process, says what the
 * role scope line is, and no longer speaks of the prompt-quality mark the user prompt left out (P3 extra 33). The fixed
 * reasoning sentences (W4-3) and the lines the showcase explains keep their words; the v19 text stays as it is.
 */
class V20SystemTextTest {

    private static final Pattern FACT_NAME = Pattern.compile("\\b[A-Z][a-z]+(?:[A-Z][a-z0-9]+)+\\b");
    private static final Pattern FIXED_REASONING = Pattern.compile("reasoning must be exactly \"([^\"]+)\"");
    private static final String TRUSTED_SIGNAL_SENTENCE =
            "A trusted internal security signal confirmed malicious activity; final autonomous action is BLOCK.";

    @Test
    void theV20SystemTextNamesOnlyFactsOfTheDictionary() {
        Set<String> names = SecurityDecisionPromptDictionary.ENTRIES.stream().map(PromptDictionaryEntry::name)
                .collect(Collectors.toSet());
        Set<String> absent = new TreeSet<>();
        Matcher matcher = FACT_NAME.matcher(v20());
        while (matcher.find()) {
            if (!names.contains(matcher.group())) {
                absent.add(matcher.group());
            }
        }
        assertThat(absent).isEmpty();
    }

    @Test
    void eachBoundaryIsStatedOnce() {
        String text = v20();
        for (String boundary : List.of("Required BLOCK boundary", "Required low-risk boundary",
                "Required elevated-risk boundary")) {
            assertThat(count(text, boundary)).as(boundary).isEqualTo(1);
        }
        assertThat(text).doesNotContain("Highest-priority action boundary");
    }

    @Test
    void theDecisionProcessFollowsTheBlocks() {
        String text = v20();
        String process = text.substring(text.indexOf("Decision process"), text.indexOf("Evidence rules"));
        List<Integer> places = new ArrayList<>();
        for (PromptBlock block : List.of(PromptBlock.USER_BASELINE, PromptBlock.SESSION, PromptBlock.REQUEST,
                PromptBlock.DECISION_FACTS, PromptBlock.PAST_RECORDS)) {
            places.add(process.indexOf(block.title()));
        }
        assertThat(places).doesNotContain(-1).isSorted();
    }

    @Test
    void theRoleScopeLineIsSaidToBeTheScopeGroupsFacts() {
        String text = v20();
        assertThat(text).contains("RoleScope compares the request with the facts of the user's scope group")
                .doesNotContain("Role scope is reachable or expected scope, not human purpose.");
    }

    @Test
    void theLowRiskBoundaryCountsOnlyAnUnmetRequirementAndAnEstablishedComparisonAsAdverse() {
        String boundary = line(v20(), "Required low-risk boundary");
        // LU-1 (P3 extra 48): a requirement PolicySatisfied states as met, a difference from a baseline that is not
        // established and a scope difference on provisional evidence no longer close the boundary while learning.
        assertThat(boundary).contains("an approval requirement that PolicySatisfied does not state as met")
                .contains("A difference in DeviationsFromBaseline while BaselineStatus is not ESTABLISHED")
                .contains("a RoleScope difference whose evidence is PROVISIONAL are not anomalies");
    }

    @Test
    void aCoveredWorkBoundaryAllowsWorkWhoseDifferencesTheCoveringRecordExplains() {
        String text = v20();
        // LU-3 (case A8T): with the policy met and every difference explained by the covering record nothing states a
        // risk, so the class of the resource alone does not hold the work back.
        assertThat(count(text, "Required covered-work boundary")).isEqualTo(1);
        assertThat(line(text, "Required covered-work boundary")).contains("AuthorizationEffect is ALLOW")
                .contains("PolicySatisfied is yes").contains("DeviationsFromBaseline names no unexplained difference")
                .contains("ResourceClass HIGH or CRITICAL alone does not prevent it");
        assertThat(text.indexOf("Required covered-work boundary"))
                .isGreaterThan(text.indexOf("Required low-risk boundary"))
                .isLessThan(text.indexOf("Required elevated-risk boundary"));
    }

    @Test
    void theReasoningLimitHoldsWhenAWordingRuleAsksForAnExplanation() {
        // LU-4: an explanation a wording rule asks for names at most two facts and keeps within 180 characters.
        assertThat(line(v20(), "reasoning must use at most 25 words and 180 characters"))
                .contains("When a wording rule asks for an explanation, name at most two facts");
    }

    @Test
    void thePromptQualityMarkTheUserPromptLeftOutIsNotSpokenOf() {
        assertThat(v20().toLowerCase()).doesNotContain("prompt-quality").doesNotContain("promptquality");
    }

    /** R4-T (Q-78 request 4): with the dictionary entry gone the v20 text neither names nor relies on it. */
    @Test
    void theFormerTrustedSignalIsNotSpokenOf() {
        assertThat(v20()).doesNotContain("TrustedSignal").doesNotContain(TRUSTED_SIGNAL_SENTENCE);
        assertThat(v19()).contains(TRUSTED_SIGNAL_SENTENCE);
    }

    @Test
    void theFixedReasoningSentencesAndTheLinesTheShowcaseExplainsStay() {
        List<String> v19Sentences = new ArrayList<>(fixedReasoning(v19()));
        v19Sentences.remove(TRUSTED_SIGNAL_SENTENCE);
        assertThat(fixedReasoning(v20())).isEqualTo(v19Sentences);
        List<String> lines = Arrays.stream(v20().split("\n")).map(String::trim).toList();
        for (String start : List.of("ALLOW =", "CHALLENGE =", "ESCALATE =", "BLOCK =", "Required low-risk boundary",
                "Required elevated-risk boundary", "6. Choose the least disruptive")) {
            assertThat(lines).as(start).anyMatch(line -> line.startsWith(start));
        }
        assertThat(lines).noneMatch(line -> line.endsWith("..."));
    }

    @Test
    void theV19SystemTextStaysAsItIs() {
        assertThat(v19()).contains("Highest-priority action boundary", "PromptQualityVerificationRequired",
                "Role scope is reachable or expected scope, not human purpose.");
        assertThat(v20()).isNotEqualTo(v19());
    }

    private static String v20() {
        return InspectionGolden.renders().get(0).systemPrompt();
    }

    private static String v19() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        return golden.render(golden.cases().get(0), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT).systemText();
    }

    private static List<String> fixedReasoning(String text) {
        List<String> sentences = new ArrayList<>();
        Matcher matcher = FIXED_REASONING.matcher(text);
        while (matcher.find()) {
            sentences.add(matcher.group(1));
        }
        return sentences;
    }

    private static String line(String text, String start) {
        return Arrays.stream(text.split("\n")).map(String::trim).filter(each -> each.startsWith(start)).findFirst()
                .orElseThrow();
    }

    private static int count(String text, String part) {
        int count = 0;
        for (int at = text.indexOf(part); at >= 0; at = text.indexOf(part, at + 1)) {
            count++;
        }
        return count;
    }
}
