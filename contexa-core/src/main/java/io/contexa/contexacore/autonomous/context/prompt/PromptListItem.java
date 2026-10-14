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

/**
 * One item of a listed prompt value with the keys {@link PromptListOrder} sorts by.
 *
 * @param text       the item as written in the prompt
 * @param name       the name the item is compared by (dimension, action, role)
 * @param rank       the number the item is compared by (hour, frequency, day of week, epoch milliseconds)
 * @param sameTarget whether a past record is about the request's target
 * @param id         the stored ID of a past record, which decides a tie in its order (W3-18); null for other items
 */
public record PromptListItem(String text, String name, long rank, boolean sameTarget, String id) {

    public static PromptListItem named(String text, String name) {
        return new PromptListItem(text, name, 0L, false, null);
    }

    public static PromptListItem ranked(String text, long rank) {
        return new PromptListItem(text, text, rank, false, null);
    }

    public static PromptListItem counted(String text, String name, long count) {
        return new PromptListItem(text, name, count, false, null);
    }

    public static PromptListItem pastRecord(String text, boolean sameTarget, long epochMillis, String id) {
        return new PromptListItem(text, text, epochMillis, sameTarget, id);
    }
}
