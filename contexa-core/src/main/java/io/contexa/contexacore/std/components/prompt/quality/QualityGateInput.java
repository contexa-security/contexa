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

import java.time.Instant;
import java.util.Collection;
import java.util.List;

/**
 * What the quality gate reads (plan 3.4).
 *
 * @param cases              the cases of the case set, each with its grade, root and the time it came in
 * @param current            the measurement of the version in use, or null when there is none
 * @param candidate          the measurement of the candidate, or null when there is none
 * @param noise              how far two measurements of the same version differ; unknown when not measured
 * @param settings           the thresholds
 * @param candidateCreatedAt when the candidate was made, or null when that is not known
 */
public record QualityGateInput(Collection<QualityCase> cases, QualityMeasurement current, QualityMeasurement candidate,
                               QualityNoise noise, QualityGateSettings settings, Instant candidateCreatedAt) {

    public QualityGateInput {
        cases = List.copyOf(cases);
        noise = noise != null ? noise : QualityNoise.unknown();
        settings = settings != null ? settings : QualityGateSettings.defaults();
    }
}
