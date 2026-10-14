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

import io.contexa.contexacore.std.components.prompt.PromptSectionPriorityClass;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

/**
 * W3-7: the order in which a prompt over its budget takes entries out, by dictionary priority: optional entries
 * first, then supporting, then high value, each from the last entry of the dictionary back (the past records before
 * the usual behaviour). A required entry is never taken out.
 */
public final class PromptBudgetTrim {

    private PromptBudgetTrim() {
    }

    public static List<PromptDictionaryEntry> order(List<PromptDictionaryEntry> dictionary,
                                                    Collection<PromptDictionaryEntry> drawn) {
        Set<PromptDictionaryEntry> present = new HashSet<>(drawn);
        List<PromptDictionaryEntry> order = new ArrayList<>();
        for (PromptSectionPriorityClass priority : List.of(PromptSectionPriorityClass.P3_OPTIONAL,
                PromptSectionPriorityClass.P2_SUPPORTING, PromptSectionPriorityClass.P1_HIGH_VALUE)) {
            for (int index = dictionary.size() - 1; index >= 0; index--) {
                PromptDictionaryEntry entry = dictionary.get(index);
                if (present.contains(entry) && priority.name().equals(entry.priority())) {
                    order.add(entry);
                }
            }
        }
        return order;
    }

    /**
     * The entries to take out, in the given order: the next entry is taken out only while the prompt without the
     * entries taken so far is over its budget, so taking out stops once the prompt fits.
     */
    public static List<PromptDictionaryEntry> withhold(List<PromptDictionaryEntry> order,
                                                       Predicate<Set<PromptDictionaryEntry>> overBudget) {
        Set<PromptDictionaryEntry> withheld = new LinkedHashSet<>();
        for (PromptDictionaryEntry entry : order) {
            if (!overBudget.test(Set.copyOf(withheld))) {
                break;
            }
            withheld.add(entry);
        }
        return List.copyOf(withheld);
    }
}
