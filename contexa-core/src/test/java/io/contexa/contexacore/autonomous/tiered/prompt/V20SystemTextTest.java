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
import java.util.stream.Stream;

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
        // A list entry (PastRecord{i}) is named by its stem where a rule speaks of its lines (W4-2 output block).
        Set<String> names = SecurityDecisionPromptDictionary.ENTRIES.stream()
                .flatMap(entry -> Stream.of(entry.name(), entry.name().replace("{i}", "")))
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
                "Required covered-work boundary", "Minimum action rules")) {
            assertThat(count(text, boundary)).as(boundary).isEqualTo(1);
        }
        // W4-4: the minimum action rules replace the elevated-risk boundary (inventory 3, line 78).
        assertThat(text).doesNotContain("Highest-priority action boundary").doesNotContain("elevated-risk boundary");
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
                .contains("ResourceClass SENSITIVE or CRITICAL alone does not prevent it");
        assertThat(text.indexOf("Required covered-work boundary"))
                .isGreaterThan(text.indexOf("Required low-risk boundary"))
                .isLessThan(text.indexOf("Otherwise prefer CHALLENGE"));
    }

    /** W4-2: the reason is one sentence of at most 30 words that states the facts behind the codes. */
    /**
     * N-WORD-2: the approval line says its decision time is not recorded and a later decision is not ruled out
     * (N-WORD-1); the covered-work boundary says that does not prevent it, so the first answer is the one the response
     * checker requires (the real server's A3T, controlled resend `p4_nword2_resend`).
     */
    @Test
    void anUnrecordedDecisionTimeDoesNotPreventCoveredWork() {
        assertThat(line(v20(), "Required covered-work boundary")).endsWith("ResourceClass SENSITIVE or CRITICAL alone"
                + " does not prevent it, and neither does an approval or ticket whose decision time is not recorded.");
    }

    @Test
    void theReasonIsOneSentenceOfAtMostThirtyWords() {
        assertThat(line(v20(), "reason:")).contains("one sentence of at most 30 words", "the facts behind the codes");
    }

    /** W4-2: the output block of the v20 text is the output contract v3 with the meaning of every reason code. */
    @Test
    void theOutputBlockIsTheOutputContract() {
        assertThat(v20()).contains(SecurityDecisionOutputContract.systemOutputBlock());
        for (String code : SecurityDecisionOutputContract.codes()) {
            assertThat(v20()).as(code).contains("- " + code + ": ");
        }
        assertThat(v20()).doesNotContain("evidenceRefs").doesNotContain("Return only one minified JSON object");
    }

    /** W4-3: the two judgement rules of the old output block stay, as evidence rules. */
    /** N-FRIC-1 (Q-87): a repeat, a new target or a large volume is a risk only with the mismatch a fact states. */
    @Test
    void anObservedDifferenceIsNoRiskByItself() {
        assertThat(v20()).contains("* A repeat count, a new target or a large volume is no evidence of risk by itself; cite it as a risk only with the mismatch it makes, which a fact states, with the work's purpose, the approval's scope or the actual behaviour.");
    }

    /** N-FRIC-1 (Q-87): the code the model cites for a repeat carries the same condition as the principle line. */
    @Test
    void theRepeatCodeSaysARepeatAloneIsNoReasonForAStrongerAction() {
        assertThat(v20()).contains("- REPEAT_IN_SESSION: the same action repeats in the session (a repeat alone is no reason for a stronger action);");
    }

    /** N-WORD-1 (Q-87): the BLOCK boundary names what is observed, not the conclusion. */
    @Test
    void theBlockBoundaryNamesWhatIsObserved() {
        assertThat(v20()).contains("a device that does not match (Device)", "automation or transport anomalies (ClientSignals)")
                .doesNotContain("device compromise", "intent or transport tampering");
    }

    @Test
    void theJudgementRulesOfTheOldOutputBlockStayAsEvidenceRules() {
        assertThat(v20()).contains("* Do not claim a missing authorization effect when AuthorizationEffect is present.");
    }

    /**
     * N-RULE-1 (G2-1 and the value words): the boundaries and evidence rules name only facts the prompt states.
     * ResourceClass is one of CRITICAL, SENSITIVE, NORMAL and PUBLIC, and no fact states a fresh-verification requirement.
     */
    @Test
    void theBoundariesAndEvidenceRulesNameOnlyFactsThePromptStates() {
        assertThat(v20()).doesNotContain("HIGH or CRITICAL").doesNotContain("fresh-verification")
                .doesNotContain("requires fresh verification")
                .contains("ResourceClass is not SENSITIVE or CRITICAL",
                        "ResourceClass SENSITIVE or CRITICAL alone does not prevent it",
                        "Unverified MFA alone is not a reason to challenge.",
                        // G2-4 (dictionary 1.4): an unknown fact is neither a match nor a mismatch.
                        "A condition that no fact states something is read on the stated lines: a fact that UNKNOWN names"
                                + " states nothing.");
    }

    /** W4-4 (plan 6.3 order 4): the minimum action rules stand once, between the actions and the boundaries. */
    @Test
    void theMinimumActionRulesStandOnceBetweenTheActionsAndTheBoundaries() {
        String text = v20();
        int rules = text.indexOf("Minimum action rules");
        assertThat(rules).isGreaterThan(text.indexOf("Actions:")).isLessThan(text.indexOf("Boundaries"))
                .isEqualTo(text.lastIndexOf("Minimum action rules"));
        assertThat(text).contains("P1 MIN_P1_IDENTITY_DEVIATION: ResourceClass is SENSITIVE or CRITICAL and DeviationsFromBaseline names at least 2 of time, day, network and device as unexplained.",
                "P2 MIN_P2_NEW_DEVICE_OR_NETWORK_EXPORT: Action is EXPORT, ResourceClass is SENSITIVE or CRITICAL, and DeviationsFromBaseline names the device or the network as unexplained.",
                "P3 MIN_P3_POLICY_NOT_SATISFIED: PolicySatisfied is no.")
                .doesNotContain("Required elevated-risk boundary");
    }

    /**
     * W4-4 (inventory 3, lines 5-7, 31 and 109): the opening keeps no rule against rules, step 6 chooses above the
     * floor, and the evidence rule says the check is no reason to move the action.
     */
    @Test
    void theOpeningTheProcessAndTheEvidenceRulesAgreeWithTheRules() {
        assertThat(v20()).doesNotContain("do not match simple rules")
                .doesNotContain("Do not pre-compensate for downstream enforcement systems.")
                .contains("Apart from the minimum action rules, make one holistic judgment",
                        "* A later check enforces the minimum action rules: do not choose a stronger or a weaker action because of it.");
        assertThat(line(v20(), "6. Choose the least disruptive"))
                .contains("never weaker than a minimum action rule that applies");
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

    /** W4-3 (Q-57 decision 2): the v20 text fixes no reason sentence; v19 keeps its own. */
    @Test
    void theV20TextFixesNoReasonSentenceAndTheLinesTheShowcaseExplainsStay() {
        assertThat(fixedReasoning(v20())).isEmpty();
        assertThat(fixedReasoning(v19())).isNotEmpty();
        List<String> lines = Arrays.stream(v20().split("\n")).map(String::trim).toList();
        for (String start : List.of("ALLOW =", "CHALLENGE =", "ESCALATE =", "BLOCK =", "Required low-risk boundary",
                "Minimum action rules", "P1 MIN_P1_IDENTITY_DEVIATION", "P2 MIN_P2_NEW_DEVICE_OR_NETWORK_EXPORT",
                "P3 MIN_P3_POLICY_NOT_SATISFIED", "6. Choose the least disruptive")) {
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
