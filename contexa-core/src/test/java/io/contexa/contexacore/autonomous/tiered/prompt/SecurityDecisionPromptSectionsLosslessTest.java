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

import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** W3-7: fact values stay whole because the dictionary forbids cutting them, not because a budget profile exists. */
class SecurityDecisionPromptSectionsLosslessTest {

    @Test
    void factValuesStayWholeExactlyWhileTheDictionaryForbidsCuttingAnyFact() {
        List<PromptDictionaryEntry> dictionary = SecurityDecisionPromptDictionary.ENTRIES;
        assertThat(SecurityDecisionPromptSections.factValuesStayWhole(dictionary)).isTrue();

        List<PromptDictionaryEntry> aFactMayBeCut = new ArrayList<>(dictionary);
        int time = indexOf(dictionary, PromptBlock.REQUEST, "Time");
        aFactMayBeCut.set(time, cuttable(dictionary.get(time), true));
        assertThat(SecurityDecisionPromptSections.factValuesStayWhole(aFactMayBeCut)).isFalse();

        List<PromptDictionaryEntry> noTextMayBeCut = new ArrayList<>(dictionary);
        int untrusted = indexOf(dictionary, PromptBlock.UNTRUSTED_TEXT, "UntrustedText{i}");
        noTextMayBeCut.set(untrusted, cuttable(dictionary.get(untrusted), false));
        assertThat(SecurityDecisionPromptSections.factValuesStayWhole(noTextMayBeCut)).isTrue();
    }

    /** W3-7: the budget counts the system prompt as the model gets it, its output format included when not native. */
    @Test
    void theBudgetCountsTheSystemPromptAsTheModelGetsIt() {
        String converter = SecurityDecisionPromptSections.modelSystemPrompt("RULES\n", StructuredOutputMode.VALIDATED_CONVERTER);
        assertThat(converter).startsWith("RULES\n\n<output_format>\n")
                .contains(SecurityDecisionContractSectionBuilder.formatInstructions())
                .endsWith("\n</output_format>");
        assertThat(SecurityDecisionPromptSections.modelSystemPrompt("RULES\n", StructuredOutputMode.NATIVE_STRUCTURED))
                .isEqualTo("RULES");
    }

    private static int indexOf(List<PromptDictionaryEntry> dictionary, PromptBlock block, String name) {
        for (int index = 0; index < dictionary.size(); index++) {
            if (dictionary.get(index).block() == block && dictionary.get(index).name().equals(name)) {
                return index;
            }
        }
        throw new IllegalArgumentException(name);
    }

    private static PromptDictionaryEntry cuttable(PromptDictionaryEntry entry, boolean truncationAllowed) {
        return new PromptDictionaryEntry(entry.block(), entry.name(), entry.meaning(), entry.sourcePath(),
                entry.formatPattern(), entry.formatExamples(), entry.missing(), entry.missingText(), entry.grades(),
                entry.decisionUse(), entry.conditional(), entry.priority(), entry.listCap(), entry.listOrder(),
                truncationAllowed, entry.preservedLabels());
    }
}
