package io.contexa.showcase.portal.reactivity;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** U6-4: the earlier measurement of the comparison must exist and be finished, or the publication names it refused. */
class PromptQualityBaselineTest {

    @Test
    void anUnknownOrUnfinishedEarlierMeasurementIsRefusedForTheComparison() {
        assertThat(PromptQualityPublications.baselineRefusal("protocol-v19", null))
                .contains(new PromptQualityPublications.Refusal(PromptQualityPublications.UNKNOWN_PROTOCOL,
                        "comparison", "protocol-v19"));
        assertThat(PromptQualityPublications.baselineRefusal("protocol-v19", false))
                .contains(new PromptQualityPublications.Refusal(PromptQualityPublications.PROTOCOL_UNFINISHED,
                        "comparison", "protocol-v19"));
        assertThat(PromptQualityPublications.baselineRefusal("protocol-v19", true)).isEmpty();
    }
}
