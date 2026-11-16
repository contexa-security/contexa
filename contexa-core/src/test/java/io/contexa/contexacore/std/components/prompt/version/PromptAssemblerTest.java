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
package io.contexa.contexacore.std.components.prompt.version;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Plan 6-1: the assembler makes a version from the product document and an organization's changes (change, delete,
 * add, include, the place of an added part, the precedence sentence, a chain of bases), and refuses a document with a
 * problem (plan 3.5: a fixed part, an unknown part or place, an empty title or text, a key twice, a prompt too long;
 * 3.6: the form).
 */
class PromptAssemblerTest {

    private final PromptVersionDocumentReader reader = new PromptVersionDocumentReader();
    private final PromptAssembler assembler = new PromptAssembler();
    private final AssembledPrompt product = SecurityDecisionPromptDocument.product();

    private PromptVersionDocument organization(String body) {
        return reader.read("prompt: cortex.security-decision\nbasedOn: v1.0\ntitle: Our rules\n" + body);
    }

    private static List<String> keys(List<PromptVersionDocument.Part> parts) {
        return parts.stream().map(PromptVersionDocument.Part::key).toList();
    }

    @Test
    void theProductVersionIsTheDocumentAsItIs() {
        assertThat(product.prompt()).isEqualTo("cortex.security-decision");
        assertThat(product.release()).isEqualTo("2026.11.16-v1.0");
        assertThat(product.organizationParts()).isFalse();
        assertThat(keys(product.drawnParts(AssembledPrompt.JUDGMENT, Set.of()))).containsExactly("mission",
                "evidence-reading", "more-reading", "similar-case-reading", "similar-case-limits", "how-to-judge",
                "responses", "honesty", "honesty-more");
        assertThat(keys(product.drawnParts("output", Set.of()))).containsExactly("output", "reason-codes",
                "citation-rules");
        assertThat(product.systemPart("decision-rules").orElseThrow().prepared()).isTrue();
        assertThat(product.effects()).isEmpty();
        assertThat(keys(product.user())).containsExactly("USER_BASELINE", "SESSION", "REQUEST", "DECISION_FACTS",
                "PAST_RECORDS", "UNKNOWN", "UNTRUSTED_TEXT", "SECOND_PASS");
        assertThat(product.user()).allMatch(PromptVersionDocument.Part::isLocked);
    }

    @Test
    void aChangeReplacesTheTextOfAChangeablePartAndBringsThePrecedenceSentence() {
        AssembledPrompt version = assembler.apply(product, organization("""
                system:
                  - key: how-to-judge
                    text: |
                      1. Weigh our duty roster first.
                """));
        String judgment = version.draw(AssembledPrompt.JUDGMENT, Set.of(), null);

        assertThat(judgment).contains("\nHow to judge:\n1. Weigh our duty roster first.\n")
                .doesNotContain("Build one story of this request");
        assertThat(version.organizationParts()).isTrue();
        assertThat(judgment).contains(product.systemPart("precedence").orElseThrow().text());
        assertThat(judgment.indexOf("Some parts of this text were written by your organization"))
                .isGreaterThan(judgment.indexOf("You are the security analyst"))
                .isLessThan(judgment.indexOf("How to read the evidence:"));
        assertThat(product.draw(AssembledPrompt.JUDGMENT, Set.of(), null))
                .doesNotContain("Some parts of this text were written by your organization");
    }

    @Test
    void aDeletionTakesAChangeablePartOut() {
        AssembledPrompt version = assembler.apply(product, organization("""
                system:
                  - key: similar-case-limits
                    delete: true
                """));

        assertThat(keys(version.drawnParts(AssembledPrompt.JUDGMENT, Set.of()))).doesNotContain("similar-case-limits");
        assertThat(version.organizationParts()).isFalse();
    }

    @Test
    void anAddedPartFollowsThePartItNamesAndTheListThatContinuesIt() {
        AssembledPrompt version = assembler.apply(product, organization("""
                system:
                  - key: org-context
                    add-after: evidence-reading
                    title: Our organization
                    text: |
                      Finance staff close the books on the last two days of a month.
                  - key: org-duty
                    add-after: evidence-reading
                    title: Our duty
                    text: |
                      On-call engineers work at night.
                user:
                  - key: org-reference
                    add-after: REQUEST
                    title: ORGANIZATION REFERENCE
                    text: |
                      Exports of the finance ledger are monthly.
                """));

        assertThat(keys(version.drawnParts(AssembledPrompt.JUDGMENT, Set.of()))).containsExactly("mission", "precedence",
                "evidence-reading", "more-reading", "similar-case-reading", "similar-case-limits", "org-context",
                "org-duty", "how-to-judge", "responses", "honesty", "honesty-more");
        assertThat(version.draw(AssembledPrompt.JUDGMENT, Set.of(), null))
                .contains("\n\nOur organization:\nFinance staff close the books on the last two days of a month.\n"
                        + "\nOur duty:\nOn-call engineers work at night.\n\nHow to judge:\n");
        assertThat(keys(version.user())).containsExactly("USER_BASELINE", "SESSION", "REQUEST", "org-reference",
                "DECISION_FACTS", "PAST_RECORDS", "UNKNOWN", "UNTRUSTED_TEXT", "SECOND_PASS");
        assertThat(version.userBlock("org-reference").orElseThrow().isLocked()).isFalse();
    }

    @Test
    void aPreparedPartIsDrawnOnlyOnceAVersionIncludesItAndALaterVersionMayTakeItOutAgain() {
        AssembledPrompt included = assembler.apply(product, organization("""
                system:
                  - key: decision-rules
                    include: true
                """));
        assertThat(keys(included.drawnParts(AssembledPrompt.JUDGMENT, Set.of()))).contains("decision-rules");
        assertThat(included.effects()).containsExactly("conclusion-lines", "fallback-on-violation");
        assertThat(included.draw(AssembledPrompt.JUDGMENT, Set.of(), null)).contains("\n\nDecision rules (they come");

        AssembledPrompt takenOut = assembler.apply(included, organization("""
                system:
                  - key: decision-rules
                    delete: true
                """));
        assertThat(keys(takenOut.drawnParts(AssembledPrompt.JUDGMENT, Set.of()))).doesNotContain("decision-rules");
        assertThat(takenOut.systemPart("decision-rules").orElseThrow().prepared()).isTrue();
        assertThat(takenOut.effects()).isEmpty();
        assertThat(takenOut.contentHash()).isEqualTo(product.contentHash());
    }

    @Test
    void aVersionStandsOnAChainOfBases() {
        AssembledPrompt second = assembler.apply(product, organization("""
                system:
                  - key: org-context
                    add-after: honesty-more
                    title: Our organization
                    text: |
                      First words.
                """));
        AssembledPrompt third = assembler.apply(second, organization("""
                system:
                  - key: org-context
                    text: |
                      Second words.
                  - key: how-to-judge
                    text: |
                      1. Our judgment.
                """));

        String judgment = third.draw(AssembledPrompt.JUDGMENT, Set.of(), null);
        assertThat(judgment).endsWith("\nOur organization:\nSecond words.\n").contains("\nHow to judge:\n1. Our judgment.\n");
        assertThat(third.organizationParts()).isTrue();
    }

    @Test
    void theSameResultHasTheSameHashAndAnotherResultAnother() {
        String change = """
                system:
                  - key: how-to-judge
                    text: |
                      1. Our judgment.
                """;
        AssembledPrompt one = assembler.apply(product, organization(change));
        AssembledPrompt two = assembler.apply(product, reader.read("prompt: cortex.security-decision\nbasedOn: v1.0\n"
                + "title: Our rules\n" + change));
        AssembledPrompt other = assembler.apply(product, organization(change.replace("Our judgment", "Their judgment")));

        assertThat(one.contentHash()).isEqualTo(two.contentHash()).isNotEqualTo(product.contentHash())
                .isNotEqualTo(other.contentHash());
        assertThat(product.contentHash()).matches("[0-9a-f]{64}");
    }

    @Test
    void aFixedPartIsNeitherChangedNorDeleted() {
        assertProblems(organization("""
                system:
                  - key: mission
                    text: |
                      You are our analyst.
                  - key: honesty
                    delete: true
                  - key: reason-codes
                    text: |
                      none
                user:
                  - key: REQUEST
                    text: |
                      Our request.
                """), PromptVersionProblem.Code.LOCKED_PART, PromptVersionProblem.Code.LOCKED_PART,
                PromptVersionProblem.Code.LOCKED_PART, PromptVersionProblem.Code.LOCKED_PART);
    }

    @Test
    void aPartOrPlaceTheBaseDoesNotHaveIsRefused() {
        assertProblems(organization("""
                system:
                  - key: no-such-part
                    text: |
                      Words.
                  - key: gone
                    delete: true
                  - key: org-a
                    add-after: no-such-part
                    title: A
                    text: |
                      Words.
                  - key: org-b
                    add-after: output
                    title: B
                    text: |
                      Words.
                  - key: how-to-judge
                    include: true
                """), PromptVersionProblem.Code.UNKNOWN_PART, PromptVersionProblem.Code.UNKNOWN_PART,
                PromptVersionProblem.Code.UNKNOWN_PLACE, PromptVersionProblem.Code.UNKNOWN_PLACE,
                PromptVersionProblem.Code.NOT_PREPARED);
    }

    @Test
    void anEmptyTitleOrTextAndAKeyTwiceAreRefused() {
        assertProblems(organization("""
                system:
                  - key: org-a
                    add-after: mission
                    text: |
                      Words.
                  - key: org-b
                    add-after: mission
                    title: B
                    text: "  "
                  - key: how-to-judge
                    text: ""
                  - key: org-c
                    add-after: mission
                    title: C
                    text: Words.
                  - key: org-c
                    add-after: mission
                    title: C
                    text: Words.
                  - key: more-reading
                    add-after: mission
                    title: D
                    text: Words.
                """), PromptVersionProblem.Code.EMPTY_TITLE, PromptVersionProblem.Code.EMPTY_TEXT,
                PromptVersionProblem.Code.EMPTY_TEXT, PromptVersionProblem.Code.DUPLICATE_KEY,
                PromptVersionProblem.Code.DUPLICATE_KEY);
    }

    @Test
    void aPromptTooLongForTheModelIsRefusedAndTheTokensAreShown() {
        PromptVersionDocument longer = organization("""
                system:
                  - key: org-context
                    add-after: mission
                    title: Our organization
                    text: |
                """ + "      " + "word ".repeat(4_000) + "\n");
        int baseTokens = assembler.check(product, longer, null).baseSystemTokens();

        PromptAssembler.Check refused = assembler.check(product, longer,
                new PromptAssembler.LengthLimit(baseTokens + 2_000, 300, 1_500));
        assertThat(refused.problems()).extracting(PromptVersionProblem::code)
                .containsExactly(PromptVersionProblem.Code.TOO_LONG);
        assertThat(refused.systemTokens()).isGreaterThan(refused.baseSystemTokens() + 4_000);

        assertThat(assembler.check(product, longer, new PromptAssembler.LengthLimit(baseTokens + 8_000, 300, 1_500))
                .passed()).isTrue();
        assertThatThrownBy(() -> assembler.apply(product, longer,
                new PromptAssembler.LengthLimit(baseTokens + 2_000, 300, 1_500)))
                .isInstanceOf(PromptVersionDocumentException.class).hasMessageContaining("TOO_LONG");
    }

    @Test
    void theDocumentMustBeAnOrganizationsChangesOfTheSamePromptOnABase() {
        assertProblems(reader.read("prompt: cortex.policy-generation\nbasedOn: v1.0\n"),
                PromptVersionProblem.Code.OTHER_PROMPT);
        assertProblems(reader.read("prompt: cortex.security-decision\ntitle: none\n"), PromptVersionProblem.Code.NO_BASE);
        assertProblems(reader.read("prompt: cortex.security-decision\nkind: rendered\nbasedOn: v1.0\n"),
                PromptVersionProblem.Code.RENDERED_DOCUMENT);
        assertProblems(organization("corrections:\n  - key: contract\n    text: Ask again.\n"),
                PromptVersionProblem.Code.LOCKED_PART);
    }

    @Test
    void theFormIsCheckedWhenTheDocumentIsRead() {
        assertRead("prompt: cortex.security-decision\nbasedOn: v1.0\nsystem:\n  - key: how-to-judge\n    locked: false\n"
                + "    text: Words.\n", PromptVersionProblem.Code.UNKNOWN_FIELD);
        assertRead("prompt: cortex.security-decision\nbasedOn: v1.0\nwhat: x\n", PromptVersionProblem.Code.UNKNOWN_FIELD);
        assertRead("prompt: cortex.security-decision\nprompt: again\n", PromptVersionProblem.Code.FORMAT);
        assertRead("- just\n- a list\n", PromptVersionProblem.Code.FORMAT);
        assertRead("basedOn: v1.0\n", PromptVersionProblem.Code.MISSING_FIELD);
        assertRead("prompt: cortex.security-decision\nkind: draft\n", PromptVersionProblem.Code.BAD_VALUE);
        assertRead("prompt: cortex.security-decision\nbasedOn: v1.0\nsystem:\n  - key: x\n    delete: true\n"
                + "    include: true\n", PromptVersionProblem.Code.BAD_VALUE);
        assertRead("prompt: cortex.security-decision\nbasedOn: v1.0\nsystem:\n  - key: x\n    delete: true\n"
                + "    text: Words.\n", PromptVersionProblem.Code.UNKNOWN_FIELD);
        assertRead("prompt: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"x\"]]]]\n",
                PromptVersionProblem.Code.FORMAT);
    }

    private void assertProblems(PromptVersionDocument changes, PromptVersionProblem.Code... codes) {
        PromptAssembler.Check check = assembler.check(product, changes, null);
        assertThat(check.problems()).extracting(PromptVersionProblem::code).containsExactlyInAnyOrder(codes);
        assertThatThrownBy(() -> assembler.apply(product, changes)).isInstanceOf(PromptVersionDocumentException.class);
    }

    private void assertRead(String yaml, PromptVersionProblem.Code code) {
        assertThatThrownBy(() -> reader.read(yaml)).isInstanceOf(PromptVersionDocumentException.class)
                .satisfies(thrown -> assertThat(((PromptVersionDocumentException) thrown).problems())
                        .extracting(PromptVersionProblem::code).contains(code));
    }
}
