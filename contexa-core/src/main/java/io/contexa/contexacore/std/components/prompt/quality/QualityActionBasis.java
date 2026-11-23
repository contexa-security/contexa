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
 * Which action of an answer the metrics are counted on (plan 3.3). The scoring is the same for both; only the column
 * differs.
 */
public enum QualityActionBasis {

    /** The answer the model gave to the prompt: the quality of the prompt. The gate uses this one. */
    FIRST_ANSWER,

    /** The action after the closing rules of the engine: what the user meets. */
    FINAL;

    /** The action of the answer on this basis, or null when the answer has none. */
    public QualityAction of(QualityAnswer answer) {
        return this == FIRST_ANSWER ? answer.firstAction() : answer.finalAction();
    }
}
