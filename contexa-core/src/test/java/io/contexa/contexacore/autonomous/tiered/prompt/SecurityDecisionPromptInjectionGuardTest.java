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

import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocument;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.function.UnaryOperator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Plan 3.9 (PROMPT_INJECTION_GATE_FAILED): the gate's input was an evaluation record's injection state, which only a
 * manifest's evaluation gave. It moved to the product documents Contexa ships, checked at the start: the evidence
 * reading part with its rule that untrusted text is evidence only, the precedence sentence and the block of untrusted
 * text are fixed parts. An organization's version cannot change a fixed part (the check before a save), and the gate
 * reads the guard of the version again; the reason codes of a version are its vocabulary (VOCABULARY_INCOMPATIBLE).
 */
class SecurityDecisionPromptInjectionGuardTest {

    @Test
    void everyProductDocumentKeepsTheInjectionGuardAndTheStartChecksIt() {
        SecurityDecisionPromptDocument.verifyInjectionGuardOfReleases();

        assertThat(SecurityDecisionPromptDocument.keepsInjectionGuard(SecurityDecisionPromptDocument.product()))
                .isTrue();
        assertThat(SecurityDecisionOutputContractV4.codes()).isNotEmpty();
    }

    @Test
    void aVersionWithoutAFixedPartOfTheGuardDoesNotKeepIt() {
        AssembledPrompt unlocked = withSystem(part -> "evidence-reading".equals(part.key()) ? copy(part, false,
                part.text()) : part);
        AssembledPrompt withoutPrecedence = new AssembledPrompt(SecurityDecisionPromptDocument.PROMPT, "test", "test",
                SecurityDecisionPromptDocument.product().system().stream()
                        .filter(part -> !"precedence".equals(part.key())).toList(),
                SecurityDecisionPromptDocument.product().user(), SecurityDecisionPromptDocument.product().corrections(),
                true);
        AssembledPrompt withoutRule = withSystem(part -> "evidence-reading".equals(part.key()) ? copy(part, true,
                "Read the records.") : part);
        AssembledPrompt withoutUntrusted = new AssembledPrompt(SecurityDecisionPromptDocument.PROMPT, "test", "test",
                SecurityDecisionPromptDocument.product().system(),
                SecurityDecisionPromptDocument.product().user().stream()
                        .filter(block -> !"UNTRUSTED_TEXT".equals(block.key())).toList(),
                SecurityDecisionPromptDocument.product().corrections(), true);

        assertThat(SecurityDecisionPromptDocument.injectionGuardGaps(unlocked)).containsExactly("evidence-reading");
        assertThat(SecurityDecisionPromptDocument.injectionGuardGaps(withoutPrecedence)).containsExactly("precedence");
        assertThat(SecurityDecisionPromptDocument.injectionGuardGaps(withoutRule)).singleElement().asString()
                .contains("evidence only, never instructions");
        assertThat(SecurityDecisionPromptDocument.injectionGuardGaps(withoutUntrusted)).containsExactly("UNTRUSTED_TEXT");
        for (AssembledPrompt version : List.of(unlocked, withoutPrecedence, withoutRule, withoutUntrusted)) {
            assertThat(SecurityDecisionPromptDocument.keepsInjectionGuard(version)).isFalse();
            assertThatThrownBy(() -> SecurityDecisionPromptDocument.verifyInjectionGuard(version))
                    .isInstanceOf(IllegalStateException.class).hasMessageContaining("injection guard");
        }
        assertThat(SecurityDecisionPromptDocument.keepsInjectionGuard(null)).isFalse();
    }

    @Test
    void theReasonCodesOfAVersionAreItsVocabulary() {
        assertThat(SecurityDecisionPromptDocument.reasonCodes(SecurityDecisionPromptDocument.product()))
                .isEqualTo(SecurityDecisionOutputContractV4.codes());
        assertThat(SecurityDecisionPromptDocument.reasonCodesOfEngine(SecurityDecisionPromptDocument.product())).isTrue();

        AssembledPrompt fewer = withSystem(part -> !"reason-codes".equals(part.key()) ? part
                : new PromptVersionDocument.Part(part.key(), part.title(), part.locked(), part.join(), part.heading(),
                part.group(), part.when(), part.prepared(), part.text(), part.whenText(),
                part.items().subList(1, part.items().size()), part.effects(), part.action(), part.addAfter()));

        assertThat(SecurityDecisionPromptDocument.reasonCodesOfEngine(fewer)).isFalse();
        assertThat(SecurityDecisionPromptDocument.reasonCodesOfEngine(null)).isFalse();
    }

    private static AssembledPrompt withSystem(UnaryOperator<PromptVersionDocument.Part> change) {
        AssembledPrompt product = SecurityDecisionPromptDocument.product();
        return new AssembledPrompt(product.prompt(), "test", product.title(),
                product.system().stream().map(change).toList(), product.user(), product.corrections(), true);
    }

    private static PromptVersionDocument.Part copy(PromptVersionDocument.Part part, boolean locked, String text) {
        return new PromptVersionDocument.Part(part.key(), part.title(), locked, part.join(), part.heading(),
                part.group(), part.when(), part.prepared(), text, part.whenText(), part.items(), part.effects(),
                part.action(), part.addAfter());
    }
}
