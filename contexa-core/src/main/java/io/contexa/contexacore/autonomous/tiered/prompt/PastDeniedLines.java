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

    /** The lines of the decisions, in their order (the latest first). */
    public static List<PromptListItem> items(PastDeniedDecisions decisions, LocalDateTime requestTime) {
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
            String text = time + " " + orUnknown(entry.actionFamily()) + " " + orNone(entry.target()) + " -> "
                    + orUnknown(entry.decidedAction()) + " (" + entry.outcome() + ")";
            items.add(PromptListItem.ranked(text, at != null ? at.toEpochSecond(ZoneOffset.UTC) * 1000L : 0L));
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
