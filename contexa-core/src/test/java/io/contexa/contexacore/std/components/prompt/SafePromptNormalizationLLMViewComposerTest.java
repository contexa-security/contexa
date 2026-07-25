/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexacore.std.components.prompt;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SafePromptNormalizationLLMViewComposerTest {

    private final SafePromptNormalizationLLMViewComposer composer =
            new SafePromptNormalizationLLMViewComposer();

    @Test
    void preservesGeneratedPromptBytesAfterLineEndingNormalization() {
        PromptViewComposition composition = composer.compose(
                "Instruction.  \r\n\r\n\r\nKeep evidence.\r\n",
                "=== EVIDENCE ===\r\nFact: value  \r\n\r\n\r\nOther: value\r\n",
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);

        assertThat(composition.llmSystemPrompt())
                .isEqualTo("Instruction.  \n\n\nKeep evidence.\n");
        assertThat(composition.llmUserPrompt())
                .isEqualTo("=== EVIDENCE ===\nFact: value  \n\n\nOther: value\n");
        assertThat(composition.compressionLedger().rawPromptParity()).isTrue();
        assertThat(composition.compressionLedger().records()).isEmpty();
    }

    @Test
    void keepsOneCompleteCopyOfAnIdenticalRepeatedSection() {
        String repeated = "=== PERSONAL WORK PROFILE ===\n"
                + "WorkProfileEvidenceState: PROVISIONAL\n"
                + "BaselineContextSummary: limited evidence";
        String prompt = repeated
                + "\n\n=== RESOURCE ===\nSensitivity: LOW\n\n"
                + repeated;

        PromptViewComposition composition = composer.compose(
                "system",
                prompt,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT,
                "gpt-5-nano");

        assertThat(count(composition.llmUserPrompt(), "=== PERSONAL WORK PROFILE ==="))
                .isEqualTo(1);
        assertThat(composition.llmUserPrompt())
                .contains("WorkProfileEvidenceState: PROVISIONAL")
                .contains("BaselineContextSummary: limited evidence")
                .contains("=== RESOURCE ===")
                .contains("Sensitivity: LOW");
        assertThat(composition.compressionLedger().transformationMode())
                .isEqualTo("NORMALIZE_AND_DEDUPLICATE");
        assertThat(composition.compressionLedger().savedCharacters()).isPositive();
    }

    @Test
    void preservesSectionsWithTheSameHeaderWhenTheirEvidenceDiffers() {
        String prompt = "=== PERSONAL WORK PROFILE ===\nBaselineContextSummary: first\n\n"
                + "=== PERSONAL WORK PROFILE ===\nBaselineContextSummary: second";

        PromptViewComposition composition = composer.compose(
                "system",
                prompt,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);

        assertThat(count(composition.llmUserPrompt(), "=== PERSONAL WORK PROFILE ==="))
                .isEqualTo(2);
        assertThat(composition.llmUserPrompt())
                .contains("BaselineContextSummary: first")
                .contains("BaselineContextSummary: second");
    }

    @Test
    void removesOnlyContradictoryAuthorizationMissingContext() {
        String prompt = "=== RESOURCE AND ACTION CONTEXT ===\nAuthorizationEffect: ALLOW\n\n"
                + "=== EXPLICIT MISSING KNOWLEDGE ===\n"
                + "- Bridge missing context: AUTHORIZATION_EFFECT.\n"
                + "- Bridge missing context: DELEGATION.";

        PromptViewComposition composition = composer.compose(
                "system",
                prompt,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);

        assertThat(composition.llmUserPrompt())
                .doesNotContain("Bridge missing context: AUTHORIZATION_EFFECT.")
                .contains("Bridge missing context: DELEGATION.")
                .contains("AuthorizationEffect: ALLOW");
    }

    @Test
    void keepsAuthorizationMissingContextWhenEffectIsUnresolved() {
        String prompt = "=== RESOURCE AND ACTION CONTEXT ===\nAuthorizationEffect: UNKNOWN\n\n"
                + "=== EXPLICIT MISSING KNOWLEDGE ===\n"
                + "- Bridge missing context: AUTHORIZATION_EFFECT.";

        PromptViewComposition composition = composer.compose(
                "system",
                prompt,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);

        assertThat(composition.llmUserPrompt())
                .contains("Bridge missing context: AUTHORIZATION_EFFECT.");
    }

    @Test
    void neverIntroducesCompactMarkersOrTruncatesLongEvidenceValues() {
        String longValue = "evidence-" + "x".repeat(600);
        PromptViewComposition composition = composer.compose(
                "system",
                "=== RAG EVIDENCE ===\nDocument: " + longValue,
                PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT);

        assertThat(composition.llmUserPrompt())
                .contains(longValue)
                .doesNotContain(
                        "CompactedLineCategories",
                        "additional lines compacted",
                        "AdditionalConfidenceWarningsCompacted");
        assertThat(composition.compressionLedger().records())
                .extracting(PromptCompressionRecord::action)
                .doesNotContain(
                        PromptCompressionAction.SUMMARIZED,
                        PromptCompressionAction.FUSED,
                        PromptCompressionAction.OMITTED);
    }

    private int count(String value, String needle) {
        int count = 0;
        int cursor = 0;
        while ((cursor = value.indexOf(needle, cursor)) >= 0) {
            count++;
            cursor += needle.length();
        }
        return count;
    }
}
