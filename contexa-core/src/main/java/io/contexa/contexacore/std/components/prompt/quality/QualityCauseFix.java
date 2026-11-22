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
 * Where an answer put down to a cause is fixed (quality plan 3.5): each cause names the part to change.
 */
public enum QualityCauseFix {
    /** The integration of the host: the facts that were missing are named, so that the host supplies them. */
    INTEGRATION,
    /** The prompt or the model. */
    PROMPT_OR_MODEL,
    /** A new version of the prompt. */
    PROMPT_VERSION,
    /** The model setting of the server. */
    MODEL_SETTING,
    /** The rule setting of the engine. */
    RULE_SETTING,
    /** The collector of the facts or the customer's own records. */
    COLLECTOR_OR_RECORDS;

    /** Whether the fix is a new version of the prompt, made in the version editor with the cases beside it. */
    public boolean opensVersionEditor() {
        return this == PROMPT_VERSION;
    }
}
