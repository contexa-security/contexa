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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;

/**
 * How the items of a listed value are ordered, so that the prompt is the same whatever order the inputs come in.
 */
public enum PromptListOrder {

    /** The value is not a list. */
    NONE,
    /** Comparison dimensions in {@link #DIMENSIONS} order. */
    DIMENSION_ORDER,
    /** Numbers ascending (hours seen). */
    ASCENDING,
    /** Frequency descending, then name ascending ({@code READ 20, EXPORT 5}). */
    FREQUENCY_DESCENDING,
    /** Name ascending in Unicode code order. */
    NAME_ASCENDING,
    /** Days of the week from Monday. */
    WEEKDAY,
    /** Time order of the requests. */
    TIME,
    /** Past records: same target first, then latest time, then the stored ID (W3-18: a similarity decides nothing). */
    PAST_RECORD;

    /** The comparison dimensions in the order of the usual-behaviour lines. */
    public static final List<String> DIMENSIONS = List.of(
            "time", "day", "network", "device", "login method", "target", "action", "class", "size", "rate");

    /**
     * The items in this order. Ties fall back to the item text, so the result never depends on the input order. A
     * value that is not a list ({@link #NONE}) keeps its items as given.
     */
    public List<PromptListItem> sort(Collection<PromptListItem> items) {
        List<PromptListItem> sorted = new ArrayList<>(items == null ? List.of() : items);
        Comparator<PromptListItem> comparator = comparator();
        if (comparator != null) {
            sorted.sort(comparator.thenComparing(PromptListItem::text, PromptListOrder::compareCodePoints));
        }
        return sorted;
    }

    /** Compares two names by Unicode code point, so that the order does not depend on a locale. */
    public static int compareCodePoints(String left, String right) {
        String first = left == null ? "" : left;
        String second = right == null ? "" : right;
        int[] firstPoints = first.codePoints().toArray();
        int[] secondPoints = second.codePoints().toArray();
        int length = Math.min(firstPoints.length, secondPoints.length);
        for (int index = 0; index < length; index++) {
            if (firstPoints[index] != secondPoints[index]) {
                return Integer.compare(firstPoints[index], secondPoints[index]);
            }
        }
        return Integer.compare(firstPoints.length, secondPoints.length);
    }

    private Comparator<PromptListItem> comparator() {
        Comparator<PromptListItem> byName = Comparator.comparing(PromptListOrder::nameOf, PromptListOrder::compareCodePoints);
        return switch (this) {
            case NONE -> null;
            case DIMENSION_ORDER -> Comparator.comparingInt(PromptListOrder::dimensionIndex).thenComparing(byName);
            case ASCENDING, WEEKDAY, TIME -> Comparator.comparingLong(PromptListItem::rank).thenComparing(byName);
            case FREQUENCY_DESCENDING -> Comparator.comparingLong(PromptListItem::rank).reversed().thenComparing(byName);
            case NAME_ASCENDING -> byName;
            case PAST_RECORD -> Comparator.comparing(PromptListItem::sameTarget).reversed()
                    .thenComparing(Comparator.comparingLong(PromptListItem::rank).reversed())
                    .thenComparing(PromptListItem::id, Comparator.nullsLast(PromptListOrder::compareCodePoints));
        };
    }

    private static String nameOf(PromptListItem item) {
        return item.name() == null ? item.text() : item.name();
    }

    private static int dimensionIndex(PromptListItem item) {
        int index = DIMENSIONS.indexOf(nameOf(item));
        return index < 0 ? DIMENSIONS.size() : index;
    }
}
