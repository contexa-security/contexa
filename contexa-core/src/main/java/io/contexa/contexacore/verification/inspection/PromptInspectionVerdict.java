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

/** The verdict of the inspection of one sealed package. */
public enum PromptInspectionVerdict {

    /** Every inspected item matched. */
    PASS,
    /** At least one item does not match its source or contract. */
    FAIL,
    /** Nothing mismatched, but some items could not be checked. */
    INCOMPLETE,
    /** The user prompt is not a dictionary prompt, so only the checks that do not read the dictionary ran. */
    NOT_APPLICABLE,
    /** The package could not be inspected; the result names why. */
    ERROR
}
