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
package io.contexa.contexacore.autonomous.context.prompt;

/** What the v20 prompt shows when a dictionary entry has no value. */
public enum PromptMissingNotation {

    /** The line is written with the entry's own missing text (for example {@code not learned}, {@code none}). */
    RENDERED_VALUE,
    /** No line is written. */
    LINE_OMITTED,
    /** No line is written; the fact's name and missing kind go to the UNKNOWN block. */
    UNKNOWN_BLOCK,
    /** The whole block is left out. */
    BLOCK_OMITTED,
    /** The entry always has a value (the request itself states it). */
    ALWAYS_PRESENT
}
