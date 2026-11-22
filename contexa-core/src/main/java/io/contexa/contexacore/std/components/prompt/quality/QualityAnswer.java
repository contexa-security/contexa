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
 * One answer of a measurement (plan 3.3): what a prompt version decided for a case in one run.
 *
 * @param caseKey             the case
 * @param run                 the run, counted from 1
 * @param firstAction         the action of the first answer, the one the model gave to the prompt; null when the
 *                            answer has none
 * @param finalAction         the action after the closing rules of the engine; null while they are not computed
 * @param reasked             whether the answer broke the contract and was asked again
 * @param decidedWithoutModel whether the model answer could not be used and the engine decided the action
 * @param citedFacts          how many facts the answer cited
 * @param accurateCitedFacts  how many of them are in the prompt and were not named by the check
 * @param decisionMillis      how long the decision took, or null
 * @param answerTokens        the tokens of the answer, or null
 * @param measurementFailed   whether the measurement itself failed, such as a model server too busy to answer; such
 *                            an answer says nothing about the prompt
 * @param failureReason       why the measurement failed, or null
 */
public record QualityAnswer(String caseKey, int run, QualityAction firstAction, QualityAction finalAction,
                            boolean reasked, boolean decidedWithoutModel, int citedFacts, int accurateCitedFacts,
                            Long decisionMillis, Integer answerTokens, boolean measurementFailed,
                            String failureReason) {

    public QualityAnswer {
        if (caseKey == null || caseKey.isBlank()) {
            throw new IllegalArgumentException("An answer names its case");
        }
        if (run < 1) {
            throw new IllegalArgumentException("The runs of a measurement are counted from 1");
        }
        if (citedFacts < 0 || accurateCitedFacts < 0 || accurateCitedFacts > citedFacts) {
            throw new IllegalArgumentException("The accurate cited facts of the case " + caseKey
                    + " are not a part of its cited facts: " + accurateCitedFacts + " of " + citedFacts);
        }
        caseKey = caseKey.trim();
    }

    /** An answer the measurement could not take. */
    public static QualityAnswer failed(String caseKey, int run, String failureReason) {
        return new QualityAnswer(caseKey, run, null, null, false, false, 0, 0, null, null, true, failureReason);
    }
}
