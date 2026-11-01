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
package io.contexa.contexacore.autonomous.baseline;

import io.micrometer.core.instrument.FunctionCounter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;

/**
 * Publishes {@link BaselineLearningService#lostLearnings()} to a Micrometer registry as
 * {@code contexa.baseline.learning.lost} (BR-S5, QF-12): the learnings that were worked out but could not be stored. It
 * sits next to the vector store's {@code contexa.vector.store.*} counters in the same registry; reading it changes no
 * decision.
 */
public class BaselineLearningLossMetrics implements MeterBinder {

    public static final String LOST = "contexa.baseline.learning.lost";

    private final BaselineLearningService baselineLearningService;

    public BaselineLearningLossMetrics(BaselineLearningService baselineLearningService) {
        this.baselineLearningService = baselineLearningService;
    }

    @Override
    public void bindTo(MeterRegistry registry) {
        // The registry holds the service weakly, so it is the service bean itself that is given, not a lambda.
        FunctionCounter.builder(LOST, baselineLearningService, BaselineLearningService::lostLearnings)
                .description("Baseline learnings that were worked out but could not be stored")
                .register(registry);
    }
}
