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

import org.junit.jupiter.api.Test;

import java.time.DayOfWeek;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W3-2: listed values are ordered by the dictionary rules (dictionary 1.5, 2.2 and 7), so the prompt is the same
 * whatever order the inputs come in (plan 8.6).
 */
class PromptListOrderTest {

    @Test
    void comparisonDimensionsFollowTheUsualLineOrder() {
        List<PromptListItem> items = List.of(
                PromptListItem.named("class CRITICAL never", "class"),
                PromptListItem.named("time 03 seen 0 of 25", "time"),
                PromptListItem.named("target GB-500 never", "target"),
                PromptListItem.named("network", "network"));

        assertThat(texts(PromptListOrder.DIMENSION_ORDER, items)).containsExactly(
                "time 03 seen 0 of 25", "network", "target GB-500 never", "class CRITICAL never");
    }

    @Test
    void hoursAscendAndFrequenciesDescendWithNamesBreakingTies() {
        List<PromptListItem> hours = List.of(PromptListItem.ranked("17", 17), PromptListItem.ranked("9", 9),
                PromptListItem.ranked("10", 10));
        List<PromptListItem> actions = List.of(PromptListItem.counted("EXPORT 5", "EXPORT", 5),
                PromptListItem.counted("READ 20", "READ", 20), PromptListItem.counted("ADMIN 5", "ADMIN", 5));

        assertThat(texts(PromptListOrder.ASCENDING, hours)).containsExactly("9", "10", "17");
        assertThat(texts(PromptListOrder.FREQUENCY_DESCENDING, actions)).containsExactly("READ 20", "ADMIN 5", "EXPORT 5");
    }

    @Test
    void namesAscendInCodePointOrderAndDaysFromMonday() {
        List<PromptListItem> roles = List.of(PromptListItem.named("SC_EXPORT", "SC_EXPORT"),
                PromptListItem.named("SC_ADMIN", "SC_ADMIN"), PromptListItem.named("Sc_audit", "Sc_audit"));
        List<PromptListItem> days = List.of(PromptListItem.ranked("Sun", DayOfWeek.SUNDAY.getValue()),
                PromptListItem.ranked("Mon", DayOfWeek.MONDAY.getValue()),
                PromptListItem.ranked("Wed", DayOfWeek.WEDNESDAY.getValue()));

        assertThat(texts(PromptListOrder.NAME_ASCENDING, roles)).containsExactly("SC_ADMIN", "SC_EXPORT", "Sc_audit");
        assertThat(texts(PromptListOrder.NAME_ASCENDING, List.of(PromptListItem.named("b", "b"),
                PromptListItem.named("C", "C"), PromptListItem.named("a", "a")))).containsExactly("C", "a", "b");
        assertThat(texts(PromptListOrder.WEEKDAY, days)).containsExactly("Mon", "Wed", "Sun");
    }

    @Test
    void requestsGoInTimeOrderAndPastRecordsPutTheSameTargetFirstThenTheLatest() {
        List<PromptListItem> requests = List.of(PromptListItem.ranked("03:19 READ", 1_000_120L),
                PromptListItem.ranked("03:17 EXPORT", 1_000_000L));
        List<PromptListItem> records = List.of(
                PromptListItem.pastRecord("older other", false, 1_000L, "id-1"),
                PromptListItem.pastRecord("newer other", false, 2_000L, "id-3"),
                PromptListItem.pastRecord("same target", true, 500L, "id-4"),
                PromptListItem.pastRecord("newer other, lower id", false, 2_000L, "id-2"));

        assertThat(texts(PromptListOrder.TIME, requests)).containsExactly("03:17 EXPORT", "03:19 READ");
        assertThat(texts(PromptListOrder.PAST_RECORD, records)).containsExactly(
                "same target", "newer other, lower id", "newer other", "older other");
    }

    @Test
    void theOrderDoesNotDependOnTheInputOrder() {
        List<PromptListItem> actions = new ArrayList<>(List.of(PromptListItem.counted("READ 20", "READ", 20),
                PromptListItem.counted("EXPORT 5", "EXPORT", 5), PromptListItem.counted("ADMIN 5", "ADMIN", 5),
                PromptListItem.counted("WRITE 2", "WRITE", 2)));
        List<String> expected = texts(PromptListOrder.FREQUENCY_DESCENDING, actions);
        Random random = new Random(20261012L);
        for (int round = 0; round < 20; round++) {
            Collections.shuffle(actions, random);
            assertThat(texts(PromptListOrder.FREQUENCY_DESCENDING, actions)).isEqualTo(expected);
        }
    }

    @Test
    void aValueThatIsNotAListKeepsItsItems() {
        List<PromptListItem> items = List.of(PromptListItem.named("b", "b"), PromptListItem.named("a", "a"));

        assertThat(texts(PromptListOrder.NONE, items)).containsExactly("b", "a");
    }

    private static List<String> texts(PromptListOrder order, List<PromptListItem> items) {
        return order.sort(items).stream().map(PromptListItem::text).toList();
    }
}
