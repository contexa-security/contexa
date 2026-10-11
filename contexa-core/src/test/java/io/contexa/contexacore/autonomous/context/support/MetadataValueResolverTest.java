package io.contexa.contexacore.autonomous.context.support;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/** W1-8: one reading of true and false for every metadata value. */
class MetadataValueResolverTest {

    @ParameterizedTest
    @ValueSource(strings = {"true", "TRUE", " yes ", "Yes", "1"})
    @DisplayName("true, yes and 1 read as true in any case")
    void readsTrue(String text) {
        assertThat(MetadataValueResolver.resolveBoolean(text)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"false", " FALSE ", "No", "0"})
    @DisplayName("false, no and 0 read as false in any case")
    void readsFalse(String text) {
        assertThat(MetadataValueResolver.resolveBoolean(text)).isFalse();
    }

    @Test
    @DisplayName("the numbers 1 and 0 read as true and false; other numbers are not a truth value")
    void readsOneAndZero() {
        assertThat(MetadataValueResolver.resolveBoolean(1)).isTrue();
        assertThat(MetadataValueResolver.resolveBoolean(0L)).isFalse();
        assertThat(MetadataValueResolver.resolveBoolean(2)).isNull();
    }

    @Test
    @DisplayName("a value that reads as neither is skipped, never taken as false")
    void skipsUnreadableValues() {
        assertThat(MetadataValueResolver.resolveBoolean("maybe", "yes")).isTrue();
        assertThat(MetadataValueResolver.resolveBoolean("maybe")).isNull();
        assertThat(MetadataValueResolver.resolveBoolean(null, " ")).isNull();
        assertThat(MetadataValueResolver.resolveBoolean((Object[]) null)).isNull();
    }

    @Test
    @DisplayName("a sequence keeps its order and repeats, from the first name that holds one (W1-12)")
    void normalizeSequenceKeepsOrderAndRepeats() {
        assertThat(MetadataValueResolver.normalizeSequence(List.of("EXPORT", " EXPORT ", "", "null", "READ"), List.of("OTHER")))
                .containsExactly("EXPORT", "EXPORT", "READ");
        assertThat(MetadataValueResolver.normalizeSequence(null, List.of(), "[READ, READ, \"EXPORT\"]"))
                .containsExactly("READ", "READ", "EXPORT");
        assertThat(MetadataValueResolver.normalizeSequence("READ,READ")).containsExactly("READ", "READ");
        assertThat(MetadataValueResolver.normalizeSequence(null, "")).isEmpty();
    }

    @Test
    @DisplayName("a sequence entry stays as written: a path or a record line is not read as an authority token (W1-12)")
    void normalizeSequenceKeepsEachEntryAsWritten() {
        assertThat(MetadataValueResolver.normalizeSequence(List.of(
                "/api/reports?authority=admin",
                "2026-09-30T03:17:00Z | POST /api/projects/GB-500/exports | EXPORT | CHALLENGE")))
                .containsExactly(
                        "/api/reports?authority=admin",
                        "2026-09-30T03:17:00Z | POST /api/projects/GB-500/exports | EXPORT | CHALLENGE");
        // A set is still a set.
        assertThat(MetadataValueResolver.normalizeStrings(List.of("EXPORT", "EXPORT"))).containsExactly("EXPORT");
    }
}
