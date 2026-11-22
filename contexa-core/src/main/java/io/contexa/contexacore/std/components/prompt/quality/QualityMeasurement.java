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

import java.util.List;
import java.util.Objects;

/**
 * One measurement (plan 3.3): a prompt version under a model setting, on a version of a case set, repeated a number
 * of times, and the answers it took.
 *
 * @param promptVersion  the prompt version that was measured
 * @param modelSetting   the model that answered and the server settings that change an answer, as one value
 * @param caseSetVersion the version of the case set, fixed by its content
 * @param repeats        how many times each case was run
 * @param answers        the answers
 */
public record QualityMeasurement(String promptVersion, String modelSetting, String caseSetVersion, int repeats,
                                 List<QualityAnswer> answers) {

    public QualityMeasurement {
        Objects.requireNonNull(promptVersion, "promptVersion");
        Objects.requireNonNull(modelSetting, "modelSetting");
        Objects.requireNonNull(caseSetVersion, "caseSetVersion");
        if (repeats < 1) {
            throw new IllegalArgumentException("A measurement runs each case at least once");
        }
        answers = List.copyOf(answers);
    }

    /**
     * Whether the two were taken the same way: the same version of the case set, the same model setting and the same
     * number of runs. Only such measurements are compared (plan 3.4).
     */
    public boolean comparableWith(QualityMeasurement other) {
        return other != null && caseSetVersion.equals(other.caseSetVersion)
                && modelSetting.equals(other.modelSetting) && repeats == other.repeats;
    }
}
