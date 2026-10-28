package io.contexa.showcase.portal.ops;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent Agent중심-화면 AC-9: the budget page reads as plain numbers for an operator: dollars with six decimals, never
 * the scientific notation a small unit cost gets from the default number formatting ("3.12E-4").
 */
class OpsBudgetTest {

    @Test
    void anAmountOfDollarsIsWrittenWithSixDecimalsAndNeverInScientificNotation() {
        assertThat(OpsBudget.plain(0.000312)).isEqualTo("0.000312");
        assertThat(OpsBudget.plain(0.967742)).isEqualTo("0.967742");
        assertThat(OpsBudget.plain(-0.003122)).isEqualTo("-0.003122");
        assertThat(OpsBudget.plain(0d)).isEqualTo("0.000000");
        assertThat(OpsBudget.plain(12.5)).isEqualTo("12.500000");
    }

    @Test
    void thePageNamesNoAmountInScientificNotation() {
        assertThat(OpsBudget.plain(1.2E-7)).doesNotContain("E");
    }
}
