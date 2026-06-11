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
package io.contexa.contexacore.std.components.prompt;

import java.util.List;

public final class PromptTokenEstimatorRegistry {

    private static final PromptTokenEstimatorRegistry DEFAULT =
            new PromptTokenEstimatorRegistry(List.of(
                    new UsageCalibratedPromptTokenEstimator(),
                    new ModelAwarePromptTokenEstimator()));

    private final List<PromptTokenEstimator> estimators;

    public PromptTokenEstimatorRegistry(List<PromptTokenEstimator> estimators) {
        this.estimators = estimators == null || estimators.isEmpty()
                ? List.of(new UsageCalibratedPromptTokenEstimator(), new ModelAwarePromptTokenEstimator())
                : List.copyOf(estimators);
    }

    public static PromptTokenEstimatorRegistry defaultRegistry() {
        return DEFAULT;
    }

    public PromptTokenEstimator resolve(String modelHint) {
        for (PromptTokenEstimator estimator : estimators) {
            if (estimator.supports(modelHint)) {
                return estimator;
            }
        }
        return estimators.get(0);
    }
}
