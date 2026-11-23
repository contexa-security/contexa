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
package io.contexa.contexacore.std.components.prompt.quality;

/**
 * Where the quality gate reads the measurements (plan 3.4): the seam between the release gate of the core and the
 * store of the cases and measurements, as {@code PromptVersionCatalog} is for the versions. The store implements it;
 * without it every version reads as one this installation cannot measure, which the gate takes as a warning only.
 *
 * <p>An implementation answers for the published case set the gate uses, the model setting the server runs and the
 * number of runs the gate compares, and says which of the five states the two measurements are in. It does not
 * decide: the gate computes the verdict from the input with its own thresholds and mode.
 */
@FunctionalInterface
public interface QualityGateSource {

    /** The detail of the source of an installation without a store of measurements. */
    String NO_SOURCE = "NO_MEASUREMENT_SOURCE";

    /**
     * The measurements of a candidate and of the version in use.
     *
     * @param scope     the registry scope the version is to decide in
     * @param prompt    the prompt key
     * @param candidate the version to be used ({@code v2.0})
     * @param current   the version the scope decides with now; null when there is none to compare with, and then only
     *                  the candidate is read (as for a version that decides outside the gate)
     * @return what was found; never null
     */
    QualityGateReading read(String scope, String prompt, String candidate, String current);

    /** No store of measurements: every version reads as one this installation cannot measure. */
    static QualityGateSource none() {
        return (scope, prompt, candidate, current) -> QualityGateReading.unmeasurable(NO_SOURCE);
    }
}
