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
 * Which action of a measured answer is outside the case's answer (quality plan 3.3, 3.5): the first answer, the one
 * the model gave to the prompt; the final action, after the closing rules of the engine; or both.
 */
public enum QualityCauseBasis {
    FIRST_ANSWER,
    FINAL,
    BOTH;

    /** Whether the first answer is wrong, so that it is the action the causes are read on. */
    public boolean firstAnswer() {
        return this != FINAL;
    }

    /** Whether the final action is wrong. */
    public boolean finalAction() {
        return this != FIRST_ANSWER;
    }
}
