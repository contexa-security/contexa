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

public record PromptSlot(
        String slotKey,
        String section,
        String label,
        Object sourceValue,
        String renderedValue,
        String narrative,
        String priority) {

    public static final String UNSCOPED_SECTION = "UNSCOPED";
    public static final String DEFAULT_PRIORITY = "STANDARD";

    public static PromptSlot line(String label, Object sourceValue, String renderedValue) {
        return new PromptSlot(
                null,
                UNSCOPED_SECTION,
                label,
                sourceValue,
                renderedValue,
                null,
                DEFAULT_PRIORITY);
    }
}
