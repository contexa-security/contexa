package io.contexa.showcase.portal.orchestrator;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.offset;

/**
 * docs/agent Agent중심-화면 AC-1: the allotment and the cost report price every model's tokens by that model's own price. A
 * single price for all models made the allotment count about 2.4 times too little of what the ledger really held.
 */
class ModelPricingTest {

    /** The ledger of 2026-10-26 (07:00 UTC onward): luna in 5,635,036 / out 486,275, sol in 140,239 / out 7,328. */
    private static final double LEDGER_OF_THE_DAY = 1.1603991;

    @Test
    void theDefaultsPriceLunaAndSolEachByItsOwnPrice() {
        ModelPricing pricing = ModelPricing.defaults(0.02);

        double luna = pricing.usd("CHAT", "gpt-6-luna", 5_635_036, 0, 486_275);
        double sol = pricing.usd("CHAT", "gpt-6.1-sol", 140_239, 0, 7_328);

        assertThat(luna).isCloseTo(0.8066411, offset(1e-7));
        assertThat(sol).isCloseTo(0.353758, offset(1e-7));
        assertThat(luna + sol).as("the day's real spend").isCloseTo(LEDGER_OF_THE_DAY, offset(1e-6));
    }

    @Test
    void oneSinglePriceCountedTheSameDayAtLessThanHalf() {
        ModelPricing single = ModelPricing.single(new Measurements.Prices(0.05, 0.40, 0.02, "old"));

        double counted = single.usd("CHAT", "gpt-6-luna", 5_635_036, 0, 486_275)
                + single.usd("CHAT", "gpt-6.1-sol", 140_239, 0, 7_328);

        assertThat(counted).isCloseTo(0.4862, offset(0.0001));
        assertThat(counted / LEDGER_OF_THE_DAY).as("the old guard counted this much of the real spend")
                .isLessThan(0.45);
    }

    @Test
    void aModelWithoutAPriceIsCountedAtTheMostExpensiveKnownPrice() {
        ModelPricing pricing = ModelPricing.defaults(0.02);

        double unknown = pricing.usd("CHAT", "some-new-model", 1_000_000, 0, 1_000_000);

        // the dearest known model is gpt-6.1-sol: 2.00 in and 10.00 out per million tokens
        assertThat(unknown).isCloseTo(12.0, offset(1e-9));
        assertThat(pricing.unknownModels()).containsExactly("some-new-model");
    }

    @Test
    void aCallWithoutAModelAndWithoutTokensCostsNothing() {
        ModelPricing pricing = ModelPricing.defaults(0.02);

        assertThat(pricing.usd("CHAT", null, 0, 0, 0)).isZero();
        assertThat(pricing.unknownModels()).isEmpty();
    }

    @Test
    void embeddingsAreCountedByTheEmbeddingPriceAndNotByAModel() {
        ModelPricing pricing = ModelPricing.defaults(0.02);

        assertThat(pricing.usd("EMBEDDING", "mxbai-embed-large", 2_000_000, 0, 0)).isCloseTo(0.04, offset(1e-9));
        assertThat(pricing.unknownModels()).isEmpty();
    }

    @Test
    void cachedPromptTokensAreCountedByTheCachedInputPrice() {
        ModelPricing pricing = ModelPricing.defaults(0.02);

        // 1,000,000 prompt tokens of which 800,000 cached, on luna: 0.2 * 0.10 + 0.8 * 0.01 = 0.028
        assertThat(pricing.usd("CHAT", "gpt-6-luna", 1_000_000, 800_000, 0)).isCloseTo(0.028, offset(1e-9));
    }

    @Test
    void theConfiguredListReplacesTheDefaults() {
        ModelPricing pricing = ModelPricing.parse("model-a=1.00/0.10/4.00;model-b=3.00/0.30/9.00", 0.02);

        assertThat(pricing.usd("CHAT", "model-a", 1_000_000, 0, 1_000_000)).isCloseTo(5.0, offset(1e-9));
        // a model of the defaults that the list does not name is unknown now, counted at the dearest listed price
        assertThat(pricing.usd("CHAT", "gpt-6-luna", 1_000_000, 0, 0)).isCloseTo(3.0, offset(1e-9));
    }

    @Test
    void aBlankListGivesTheDefaults() {
        assertThat(ModelPricing.parse("  ", 0.02).usd("CHAT", "gpt-6-luna", 1_000_000, 0, 0))
                .isCloseTo(0.10, offset(1e-9));
    }
}
