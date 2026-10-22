package io.contexa.showcase.portal.lab;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Review before the guide videos (2026-10-21, B-08): the lab result says whether the visitor's call was right only for
 * a case sent as designed whose answer is set in advance, and only for a call of attack or normal work.
 */
class LabRecentTest {

    @Test
    void aCallIsScoredOnlyForADesignedCaseWithASetAnswer() {
        assertThat(LabStore.callRight(true, "ATTACK", "THREAT")).isTrue();
        assertThat(LabStore.callRight(true, "NORMAL", "THREAT")).isFalse();
        assertThat(LabStore.callRight(true, "NORMAL", "NORMAL")).isTrue();
        assertThat(LabStore.callRight(true, "ATTACK", "NORMAL")).isFalse();
        assertThat(LabStore.callRight(true, "UNSURE", "THREAT")).as("no call to score").isNull();
        assertThat(LabStore.callRight(true, null, "THREAT")).isNull();
        assertThat(LabStore.callRight(true, "ATTACK", "UNCERTAIN")).as("no set answer").isNull();
        assertThat(LabStore.callRight(false, "ATTACK", "THREAT")).as("a condition changed").isNull();
    }
}
