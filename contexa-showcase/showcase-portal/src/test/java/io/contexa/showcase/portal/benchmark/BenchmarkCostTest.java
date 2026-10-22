/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.showcase.portal.benchmark;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

/**
 * 판정층 E-11 (docs/showcase/판정층-수정계획.md): the layers run on different models, so each model call is priced by
 * its own model; a model with calls and no price makes the cost per decision unknown rather than priced as another.
 */
class BenchmarkCostTest {

    /** Prices of two models of this test, not of real ones. */
    private static final Map<String, BenchmarkService.Price> PRICES = Map.of(
            "model-one", new BenchmarkService.Price(0.10, 0.01, 0.50),
            "model-two", new BenchmarkService.Price(1.00, 0.10, 4.00));

    @Test
    void eachModelsCallsArePricedByThatModel() {
        Map<String, BenchmarkService.ModelTokens> byModel = new LinkedHashMap<>();
        byModel.put("model-one", new BenchmarkService.ModelTokens(3_000_000, 1_000_000, 200_000));
        byModel.put("model-two", new BenchmarkService.ModelTokens(1_000_000, 0, 100_000));

        Double cost = BenchmarkService.costPerDecision(byModel, PRICES, 10);

        // one: 2.0M x 0.10 + 1.0M x 0.01 + 0.2M x 0.50 = 0.31; two: 1.0M x 1.00 + 0.1M x 4.00 = 1.40; per 10 decisions.
        assertThat(cost).isCloseTo(0.171, within(1e-9));
    }

    @Test
    void aModelWithCallsAndNoPriceMakesTheCostUnknown() {
        Map<String, BenchmarkService.ModelTokens> byModel = new HashMap<>();
        byModel.put("model-one", new BenchmarkService.ModelTokens(1_000_000, 0, 0));
        byModel.put("model-unpriced", new BenchmarkService.ModelTokens(1_000, 0, 10));

        assertThat(BenchmarkService.costPerDecision(byModel, PRICES, 4)).isNull();
    }

    @Test
    void noDecisionsHaveNoCostAndDecisionsWithoutModelCallsCostNothing() {
        assertThat(BenchmarkService.costPerDecision(Map.of(), PRICES, 0)).isNull();
        assertThat(BenchmarkService.costPerDecision(Map.of(), PRICES, 3)).isEqualTo(0.0);
    }
}
