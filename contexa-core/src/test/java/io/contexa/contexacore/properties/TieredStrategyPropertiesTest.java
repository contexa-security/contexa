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

    /**
     * W4-6 (deep analysis G-5): the defaults fit reasoning models, whose reasoning tokens count against the output
     * limit: Layer1 2,048 and Layer2 2,560 output tokens, reasoning effort low (the settings the showcase measurements
     * ran without a cut answer).
     */
    @Test
    void theOutputLimitsAndTheReasoningEffortFitReasoningModels() {
        TieredStrategyProperties properties = new TieredStrategyProperties();

        assertThat(properties.getLayer1().getMaxOutputTokens()).isEqualTo(2048);
        assertThat(properties.getLayer2().getMaxOutputTokens()).isEqualTo(2560);
        assertThat(properties.getLayer1().getOpenAiReasoningEffort()).isEqualTo("low");
        assertThat(properties.getLayer2().getOpenAiReasoningEffort()).isEqualTo("low");
    }

    /** W4-6: a security decision fixes the determinism settings a provider takes: temperature 0 and one seed. */
    @Test
    void theDeterminismSettingsAreFixed() {
        TieredStrategyProperties.Determinism determinism = new TieredStrategyProperties().getDeterminism();

        assertThat(determinism.getTemperature()).isEqualTo(0.0d);
        assertThat(determinism.getSeed()).isEqualTo(1);
    }
}
