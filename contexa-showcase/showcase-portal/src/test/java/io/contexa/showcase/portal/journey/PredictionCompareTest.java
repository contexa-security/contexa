package io.contexa.showcase.portal.journey;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The visitor's call against Contexa's actual judgment (docs/showcase/화면재편-구현계획.md P-4, F-5): the result screen
 * says whether the call was the same judgment, or at least the same handling (both keep the data in, or both let it
 * through), from the server, so the screen picks a sentence and computes nothing.
 */
class PredictionCompareTest {

    @Test
    void theSameJudgmentIsAlsoTheSameHandling() {
        assertThat(JourneyViews.sameAction("CHALLENGE", "CHALLENGE")).isTrue();
        assertThat(JourneyViews.sameStop("CHALLENGE", "CHALLENGE")).isTrue();
    }

    @Test
    void aCheckAndAHoldDifferButBothKeepTheDataIn() {
        assertThat(JourneyViews.sameAction("CHALLENGE", "ESCALATE")).isFalse();
        assertThat(JourneyViews.sameStop("CHALLENGE", "ESCALATE")).isTrue();
        assertThat(JourneyViews.sameStop("BLOCK", "ESCALATE")).isTrue();
    }

    @Test
    void passingIsTheOtherHandling() {
        assertThat(JourneyViews.sameStop("ALLOW", "ESCALATE")).isFalse();
        assertThat(JourneyViews.sameStop("CHALLENGE", "ALLOW")).isFalse();
        assertThat(JourneyViews.sameStop("ALLOW", "ALLOW")).isTrue();
    }

    @Test
    void nothingIsSaidBeforeTheCallOrTheRun() {
        assertThat(JourneyViews.sameAction(null, "ESCALATE")).isNull();
        assertThat(JourneyViews.sameStop("CHALLENGE", null)).isNull();
    }
}
