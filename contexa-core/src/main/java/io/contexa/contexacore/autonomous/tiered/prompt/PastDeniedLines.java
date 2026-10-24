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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.decision.RelativeTime;
import io.contexa.contexacore.autonomous.context.prompt.PromptListItem;
import io.contexa.contexacore.autonomous.context.support.PastDeniedDecisions;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.TextStyle;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The PastDeniedDecision lines of the past records block (W5-4, dictionary 2.5): the time as the past record lines
 * write it, then {@code 〈action〉 〈target〉 -> 〈decided action〉 (〈outcome〉)}. The prompt inspector draws the
 * same lines from the sealed decisions.
 */
public final class PastDeniedLines {

    private PastDeniedLines() {
    }

    /** docs/agent A3-5: the target of a v21 line, whose value is an untrusted text. */
    public static final String TARGET_APART = "target-in-UNTRUSTED-TEXT";

    /** The lines of the decisions, in their order (the latest first). */
    public static List<PromptListItem> items(PastDeniedDecisions decisions, LocalDateTime requestTime) {
        return items(decisions, requestTime, false);
    }

    /**
     * The lines of the decisions; a v21 line ({@code targetsApart}) writes {@link #TARGET_APART} in place of the target
     * and carries the target as the item's name (A3-5).
     */
    public static List<PromptListItem> items(PastDeniedDecisions decisions, LocalDateTime requestTime,
                                             boolean targetsApart) {
        if (decisions == null || decisions.entries().isEmpty()) {
            return List.of();
        }
        List<PromptListItem> items = new ArrayList<>();
        for (PastDeniedDecisions.Entry entry : decisions.entries()) {
            LocalDateTime at = entry.at();
            String relative = RelativeTime.of(at, requestTime);
            String time = at == null ? PastRecordLines.TIME_NOT_RECORDED
                    : String.format(Locale.ROOT, PastRecordLineValues.TIME_FORMAT, at.getMonthValue(), at.getDayOfMonth(),
                    at.getDayOfWeek().getDisplayName(TextStyle.SHORT, Locale.ROOT), at.getHour(), at.getMinute())
                    + (relative != null ? " (" + relative + ")" : "");
            boolean apart = targetsApart && entry.target() != null;
            String text = time + " " + orUnknown(entry.actionFamily()) + " " + (apart ? TARGET_APART : orNone(entry.target()))
                    + " -> " + orUnknown(entry.decidedAction()) + " (" + entry.outcome() + ")";
            long rank = at != null ? at.toEpochSecond(ZoneOffset.UTC) * 1000L : 0L;
            items.add(apart ? new PromptListItem(text, entry.target(), rank, false, null) : PromptListItem.ranked(text, rank));
        }
        return List.copyOf(items);
    }

    private static String orUnknown(String value) {
        return value != null ? value.toUpperCase(Locale.ROOT) : "UNKNOWN";
    }

    private static String orNone(String value) {
        return value != null ? value.replace(' ', '_') : "no-target";
    }
}
