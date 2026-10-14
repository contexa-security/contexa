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
package io.contexa.contexacore.verification.inspection;

/**
 * One check of the prompt inspector: what it compares with what, over one sealed package. A check points at problems;
 * it never changes the prompt, the decision or anything else.
 */
public interface PromptInspectionCheck {

    /** The check code findings carry. */
    String code();

    /** Whether the check reads the user prompt as a v20 dictionary prompt; such checks skip other layouts. */
    boolean dictionaryPromptOnly();

    /** Records every item the check looks at on the tally's subject. */
    void inspect(PromptInspectionTally tally);
}
