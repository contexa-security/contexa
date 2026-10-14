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

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * One entry of the v20 prompt dictionary: a line the prompt may write, what it means, where its value comes from, the
 * form of the value, what is written without a value, the grade of its source, what the decision uses it for, and how
 * it may be shortened. A name ending in {@code {i}} stands for numbered lines ({@code PastRecord1}, {@code PastRecord2}).
 *
 * @param block            the block the line belongs to
 * @param name             the line label
 * @param meaning          what the fact means
 * @param sourcePath       where the value comes from (code path or the work item that produces it)
 * @param formatPattern    regular expression the rendered value matches as a whole
 * @param formatExamples   rendered values the pattern accepts (measured values or forms with placeholders)
 * @param missing          what the prompt shows without a value
 * @param missingText      the text written without a value, when {@code missing} writes one
 * @param grades           the source grades the value may carry
 * @param decisionUse      what the decision uses the fact for (reason codes, minimum response rules, context)
 * @param conditional      written only when a value exists
 * @param priority         order of shortening under a budget, a {@link PromptSectionPriorityClass} name as in the
 *                         section plans and the slot contract rows:
 *                         {@link #PRIORITY_REQUIRED} is never cut
 * @param listCap          largest number of listed items before {@code +n more}; null when there is no cap
 * @param listOrder        how listed items are ordered
 * @param truncationAllowed whether characters of the value may be cut (untrusted text only)
 * @param preservedLabels  labels of the v19 prompt and of the canonical context whose facts this entry carries
 */
public record PromptDictionaryEntry(
        PromptBlock block,
        String name,
        String meaning,
        String sourcePath,
        String formatPattern,
        List<String> formatExamples,
        PromptMissingNotation missing,
        String missingText,
        Set<PromptSourceGrade> grades,
        String decisionUse,
        boolean conditional,
        String priority,
        Integer listCap,
        PromptListOrder listOrder,
        boolean truncationAllowed,
        List<String> preservedLabels) {

    /** Cited by reason codes or minimum response rules. */
    public static final String PRIORITY_REQUIRED = PromptSectionPriorityClass.P0_REQUIRED.name();
    /** Context of the decision. */
    public static final String PRIORITY_HIGH_VALUE = PromptSectionPriorityClass.P1_HIGH_VALUE.name();
    /** Reference only. */
    public static final String PRIORITY_SUPPORTING = PromptSectionPriorityClass.P2_SUPPORTING.name();

    private static final String INDEX_SUFFIX = "{i}";

    public PromptDictionaryEntry {
        Objects.requireNonNull(block, "block");
        Objects.requireNonNull(name, "name");
        formatExamples = formatExamples == null ? List.of() : List.copyOf(formatExamples);
        grades = grades == null ? Set.of() : Set.copyOf(grades);
        listOrder = listOrder == null ? PromptListOrder.NONE : listOrder;
        preservedLabels = preservedLabels == null ? List.of() : List.copyOf(preservedLabels);
    }

    /** The fact id prefix of the entry's block, or null when the block's lines are not cited by id. */
    public String factPrefix() {
        return block.factPrefix();
    }

    /** Whether the entry stands for numbered lines. */
    public boolean indexed() {
        return name.endsWith(INDEX_SUFFIX);
    }

    /** The label of a numbered entry without its number ({@code PastRecord} for {@code PastRecord{i}}); else the name. */
    public String stem() {
        return indexed() ? name.substring(0, name.length() - INDEX_SUFFIX.length()) : name;
    }

    /** Whether a rendered line label is this entry ({@code PastRecord3} for {@code PastRecord{i}}). */
    public boolean matchesLabel(String label) {
        if (label == null) {
            return false;
        }
        if (!indexed()) {
            return name.equals(label);
        }
        String stem = stem();
        return label.length() > stem.length() && label.startsWith(stem)
                && label.substring(stem.length()).chars().allMatch(Character::isDigit);
    }

    /** Whether a rendered value has the entry's form. */
    public boolean acceptsValue(String value) {
        return value != null && formatPattern != null && Pattern.compile(formatPattern).matcher(value).matches();
    }
}
