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

public record PromptSlotPlan(
        String slotKey,
        String sectionKey,
        String labelKey,
        String canonicalContextPath,
        String sourceProducer,
        String priority,
        String truncationPolicy) {

    public static PromptSlotPlan unscoped(String sectionKey, String labelKey) {
        return new PromptSlotPlan(
                null,
                sectionKey == null || sectionKey.isBlank() ? PromptSlot.UNSCOPED_SECTION : sectionKey.trim(),
                labelKey == null ? "" : labelKey.trim(),
                null,
                null,
                PromptSlot.DEFAULT_PRIORITY,
                null);
    }

    public PromptSlot bind(Object sourceValue, String renderedValue, String narrative) {
        return new PromptSlot(
                slotKey,
                sectionKey,
                labelKey,
                sourceValue,
                renderedValue,
                narrative,
                priority);
    }
}
