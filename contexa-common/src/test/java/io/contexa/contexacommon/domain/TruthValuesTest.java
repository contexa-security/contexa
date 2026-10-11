package io.contexa.contexacommon.domain;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/** W1-8: one reading of true and false for attributes, headers and metadata. */
class TruthValuesTest {

    @ParameterizedTest
    @ValueSource(strings = {"true", "TRUE", " yes ", "Y", "1"})
    void readsTrue(String text) {
        assertThat(TruthValues.parse(text)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"false", "No", "n", "0"})
    void readsFalse(String text) {
        assertThat(TruthValues.parse(text)).isFalse();
    }

    @Test
    void readsBooleansAndOnlyTheNumbersOneAndZero() {
        assertThat(TruthValues.parse(Boolean.TRUE)).isTrue();
        assertThat(TruthValues.parse(1)).isTrue();
        assertThat(TruthValues.parse(0.0)).isFalse();
        assertThat(TruthValues.parse(2)).isNull();
    }

    @Test
    void anythingElseIsNotATruthValue() {
        assertThat(TruthValues.parse("maybe")).isNull();
        assertThat(TruthValues.parse("NULL_VALUE")).isNull();
        assertThat(TruthValues.parse(" ")).isNull();
        assertThat(TruthValues.first("maybe", null, "no")).isFalse();
        assertThat(TruthValues.first((Object[]) null)).isNull();
    }
}
