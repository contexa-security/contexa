package io.contexa.showcase.portal.anatomy;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W4-7: a step without stored texts says why, as a fact the visitor can check: past the 90-day retention, or never
 * captured (a run before the capture began, or a decision without a model call).
 */
class AnatomyStoreTest {

    private static final Instant NOW = Instant.parse("2027-01-10T00:00:00Z");
    private static final Duration NINETY_DAYS = Duration.ofDays(90);

    @Test
    void aRunOlderThanTheRetentionHadItsTextsDeleted() {
        assertThat(AnatomyStore.missing(NOW.minus(Duration.ofDays(91)), NOW, NINETY_DAYS))
                .isEqualTo(AnatomyStore.PAST_RETENTION);
    }

    @Test
    void aYoungerRunWithoutTextsNeverHadThem() {
        assertThat(AnatomyStore.missing(NOW.minus(Duration.ofDays(89)), NOW, NINETY_DAYS))
                .isEqualTo(AnatomyStore.NOT_COLLECTED);
        assertThat(AnatomyStore.missing(NOW.minus(NINETY_DAYS), NOW, NINETY_DAYS))
                .as("exactly at the cut-off the job has not deleted them yet").isEqualTo(AnatomyStore.NOT_COLLECTED);
    }
}
