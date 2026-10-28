package io.contexa.showcase.portal.orchestrator;

import io.contexa.showcase.portal.benchmark.BenchmarkService;
import io.contexa.showcase.portal.benchmark.BenchmarkService.Price;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Comparator;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

/**
 * docs/agent Agent중심-화면 AC-1: what a model's tokens cost, each model by its own price (US dollars per one million
 * tokens: input, cached input, output). The live allotment and the cost report used one price for every model, so a
 * day on {@code gpt-6-luna} and {@code gpt-6.1-sol} was counted at less than half of what the ledger held (sol alone is
 * twenty times dearer).
 * <p>
 * A model with no price is counted at the dearest known price and reported once, because the allotment is a safety
 * valve and a guess must not fall below the truth. (The benchmark does the opposite, on purpose: it leaves the cost
 * per decision empty rather than price a model as another.)
 */
public final class ModelPricing {

    private static final Logger log = LoggerFactory.getLogger(ModelPricing.class);
    private static final double PER = 1_000_000d;

    /** The prices read on 2026-10-07 and 2026-10-20 from the providers' price lists (the portal's benchmark list). */
    private static final String DEFAULTS = "gpt-5-nano=0.05/0.005/0.40;gpt-6-luna=0.10/0.01/0.50;"
            + "gpt-6.1-sol=2.00/0.10/10.00;claude-haiku-5-5=0.10/0.01/0.50";

    private final Map<String, Price> prices;
    private final Price dearest;
    private final double embeddingInput;
    private final boolean single;
    private final Set<String> unknown = ConcurrentHashMap.newKeySet();

    private ModelPricing(Map<String, Price> prices, double embeddingInput, boolean single) {
        this.prices = Map.copyOf(prices);
        this.embeddingInput = embeddingInput;
        this.single = single;
        this.dearest = prices.values().stream()
                .max(Comparator.comparingDouble((Price price) -> price.input() + price.output()))
                .orElse(new Price(0, 0, 0));
    }

    /** The built-in prices. */
    public static ModelPricing defaults(double embeddingInput) {
        return new ModelPricing(BenchmarkService.prices(DEFAULTS), embeddingInput, false);
    }

    /**
     * @param configured "model=input/cachedInput/output;..." as the benchmark's list (showcase.benchmark.prices); the
     *                   built-in prices when blank
     */
    public static ModelPricing parse(String configured, double embeddingInput) {
        if (configured == null || configured.isBlank()) {
            return defaults(embeddingInput);
        }
        Map<String, Price> parsed = BenchmarkService.prices(configured);
        return parsed.isEmpty() ? defaults(embeddingInput) : new ModelPricing(parsed, embeddingInput, false);
    }

    /** Every model priced by one price (the allotment before AC-1); for the tests that name their own price. */
    public static ModelPricing single(Measurements.Prices prices) {
        Price price = new Price(prices.chatInput(), prices.chatInput(), prices.chatOutput());
        return new ModelPricing(Map.of("*", price), prices.embeddingInput(), true);
    }

    /**
     * The cost of the calls of one model in dollars.
     *
     * @param kind         CHAT, AGENT_CHAT or EMBEDDING
     * @param prompt       prompt tokens, the cached ones included
     * @param cachedPrompt the cached part of the prompt tokens (0 where the provider gave none)
     */
    public double usd(String kind, String model, long prompt, long cachedPrompt, long completion) {
        if ("EMBEDDING".equals(kind)) {
            return prompt * embeddingInput / PER;
        }
        if (prompt == 0 && completion == 0) {
            return 0d;
        }
        Price price = priceOf(model);
        long cached = Math.min(Math.max(cachedPrompt, 0), prompt);
        return ((prompt - cached) * price.input() + cached * price.cachedInput() + completion * price.output()) / PER;
    }

    /** The prices of a model; the dearest known one, reported once, for a model with none. */
    Price priceOf(String model) {
        if (single) {
            return prices.get("*");
        }
        Price price = model == null ? null : prices.get(model);
        if (price != null) {
            return price;
        }
        String name = model == null ? "(none)" : model;
        if (unknown.add(name)) {
            log.error("[ModelPricing] No price for model {}: counted at the dearest known price (input {}, output {} per "
                    + "million tokens); add it to showcase.benchmark.prices", name, dearest.input(), dearest.output());
        }
        return dearest;
    }

    /** The prices as a report shows them: each model's, the embedding price and the models counted without a price. */
    public Map<String, Object> describe() {
        Map<String, Object> view = new java.util.LinkedHashMap<>();
        Map<String, Object> models = new java.util.TreeMap<>();
        prices.forEach((model, price) -> models.put(model, Map.of("input", price.input(),
                "cachedInput", price.cachedInput(), "output", price.output())));
        view.put("models", models);
        view.put("embeddingInput", embeddingInput);
        view.put("unknownModels", unknownModels());
        return view;
    }

    /** The models counted at the dearest price because they had none, in name order. */
    public Set<String> unknownModels() {
        return new TreeSet<>(unknown);
    }
}
