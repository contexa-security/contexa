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
     * limit: Layer1 4,096 and Layer2 2,560 output tokens, reasoning effort low. QF-3: the Layer1 limit was 2,048, the
     * setting the showcase measurements ran without a cut answer on OpenAI models; on claude-haiku-5-5 797 of 2,373
     * stored Layer 1 answers (33.6%) reached 2,048 output tokens and 516 (21.7%) were not usable JSON. A replay of the
     * same requests with 4,096 left none cut at the same median output length.
     */
    @Test
    void theOutputLimitsAndTheReasoningEffortFitReasoningModels() {
        TieredStrategyProperties properties = new TieredStrategyProperties();

        assertThat(properties.getLayer1().getMaxOutputTokens()).isEqualTo(4096);
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
