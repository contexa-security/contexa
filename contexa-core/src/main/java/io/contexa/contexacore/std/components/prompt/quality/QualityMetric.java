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
 * The rates of a measurement (plan 3.3). Each is a share of answers over all runs, so its value is the average of the
 * runs; the decision time and the answer tokens are not rates and are given as a spread.
 */
public enum QualityMetric {

    /** Of the answers to cases that must be stopped, those that allowed. */
    MISS(true),

    /** Of the answers to cases that must be allowed, those outside the allowed actions. */
    FALSE_STOP(true),

    /** Of the answers to cases that must be allowed, those that did not allow: a version that challenges everything. */
    FRICTION(true),

    /** Of the answers to cases whose right answer has no BLOCK, those that blocked. */
    OVER_BLOCK(true),

    /** Of all answers, those inside the allowed actions. */
    ACTION_HIT(false),

    /** Of all answers, those whose first answer is ESCALATE: a version that only defers. */
    DEFERRAL(true),

    /** Of the cases with two or more answers, those whose answers all took the same action. */
    CONSISTENCY(false),

    /** Of the cited facts, those in the prompt that the check did not name. */
    CITATION_ACCURACY(false),

    /** Of all answers, those that broke the contract and were asked again. */
    REASK(true),

    /** Of all answers, those the engine decided because the model answer could not be used. */
    MODEL_LESS(true);

    private final boolean lowerIsBetter;

    QualityMetric(boolean lowerIsBetter) {
        this.lowerIsBetter = lowerIsBetter;
    }

    public boolean lowerIsBetter() {
        return lowerIsBetter;
    }
}
