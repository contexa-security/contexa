package io.contexa.contexacore.properties;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TieredStrategyPropertiesTest {

    /**
     * P3-EXTRA-4: an interactive request waits 600 ms for its past record search. Of 1,000 searches on the showcase
     * engine the 99th percentile took 524 ms and none that finished in time took over 497 ms, while 500 ms timed out
     * 5.8% of them and gave the same case different prompts.
     */
    @Test
    void anInteractiveRequestWaitsLongEnoughForNearlyEveryPastRecordSearch() {
        assertThat(new TieredStrategyProperties().getLayer1().getTimeout().getInteractiveRagWaitMs()).isEqualTo(600);
    }
}
