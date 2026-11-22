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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * An answer of a measurement as the cause classification reads it (quality plan 3.3, 3.5): its actions before and
 * after the rules of the engine, whether the engine set the action without the model, the citations and how long the
 * model calls of the first pass took.
 *
 * @param caseKey             the case
 * @param run                 the run, counted from 1
 * @param firstAction         the action of the first answer as the pipeline gave it; null when it gave none of the four
 * @param modelAction         the action the model's own answer gave before a rule of the engine replaced it; null when
 *                            no action could be read from the model
 * @param finalAction         the action after the closing rules; null when they could not be computed
 * @param decidedWithoutModel whether the model's answer could not be used and the engine set the action: no usable
 *                            form, a contract still broken after the retry, an answer cut or refused
 * @param secondPassUnusable  whether the second pass answered in no usable form and the closing rules replaced its action
 * @param citations           what the response check found of the citations of the first answer
 * @param firstPassCallMillis how long each model call of the first pass took, in their order; null for a call whose
 *                            time was not measured
 * @param decisionMillis      the wall time of the replay, or null
 * @param measurementFailed   whether the measurement itself failed, so the answer says nothing about the prompt
 */
public record QualityCauseAnswer(String caseKey, int run, QualityAction firstAction, QualityAction modelAction,
                                 QualityAction finalAction, boolean decidedWithoutModel, boolean secondPassUnusable,
                                 QualityCauseCitations citations, List<Long> firstPassCallMillis, Long decisionMillis,
                                 boolean measurementFailed) {

    public QualityCauseAnswer {
        if (caseKey == null || caseKey.isBlank()) {
            throw new IllegalArgumentException("An answer names its case");
        }
        if (run < 1) {
            throw new IllegalArgumentException("The runs of a measurement are counted from 1");
        }
        caseKey = caseKey.trim();
        citations = citations != null ? citations : QualityCauseCitations.NOT_CHECKED;
        // A call whose time was not measured stays in its place as null, so the list is not copied with List.copyOf.
        firstPassCallMillis = firstPassCallMillis == null ? List.of()
                : Collections.unmodifiableList(new ArrayList<>(firstPassCallMillis));
    }

    /** The action of the answer on the basis: the first answer, or the final action. */
    public QualityAction action(boolean firstAnswer) {
        return firstAnswer ? firstAction : finalAction;
    }
}
