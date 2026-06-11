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

import org.springframework.util.StringUtils;

import java.util.List;

public class PromptSlotRenderer {

    public String render(List<PromptSlot> slots) {
        if (slots == null || slots.isEmpty()) {
            return "";
        }
        StringBuilder rendered = new StringBuilder();
        for (PromptSlot slot : slots) {
            rendered.append(renderLine(slot));
        }
        return rendered.toString();
    }

    public String renderLine(PromptSlot slot) {
        if (slot == null || !StringUtils.hasText(slot.label()) || !StringUtils.hasText(slot.renderedValue())) {
            return "";
        }
        return slot.label() + ": " + slot.renderedValue() + "\n";
    }
}
