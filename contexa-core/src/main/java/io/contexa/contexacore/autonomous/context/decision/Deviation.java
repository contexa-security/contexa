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
package io.contexa.contexacore.autonomous.context.decision;

import io.contexa.contexacore.autonomous.baseline.BaselineView;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.TextStyle;
import java.util.Locale;

/**
 * The request compared with the usual behaviour on one dimension (W2-5).
 *
 * @param dimension   the dimension
 * @param current     the request's value as the prompt names it ({@code 03}, {@code Chrome/140 on WINDOWS})
 * @param compared    whether there was a usual behaviour to compare with; without one the difference is unknown
 * @param different   whether the value was not seen in the usual behaviour (false when not compared)
 * @param seen        how many observations of the usual behaviour held the value, null when not counted
 * @param of          how many observations were counted, null when not counted
 * @param usual       the usual value when a count does not say it ({@code up to 29 items per export}), else null
 * @param explanation EXPLAINED, UNEXPLAINED, NOT_ESTABLISHED while the personal baseline is still learned (LU-1) or,
 *                    without a usual behaviour, UNKNOWN; null for a value seen before
 * @param explainedBy the record that explains the difference ({@code APR-...}, a trip), null otherwise
 * @param observed    how the request's value was seen: on how many days, first, last, and last in the retention
 *                    (W5-10 D1~D3); null when the view does not say
 * @param notComparedReason why the dimension was not compared (W5-10 D1); null when compared or not known
 */
public record Deviation(
        DeviationDimension dimension,
        String current,
        boolean compared,
        boolean different,
        Integer seen,
        Integer of,
        String usual,
        Explanation explanation,
        String explainedBy,
        BaselineView.Seen observed,
        String notComparedReason) {

    /** A comparison without how the value was seen over days (before W5-10). */
    public Deviation(DeviationDimension dimension, String current, boolean compared, boolean different, Integer seen,
                     Integer of, String usual, Explanation explanation, String explainedBy) {
        this(dimension, current, compared, different, seen, of, usual, explanation, explainedBy, null, null);
    }

    public enum Explanation {
        EXPLAINED,
        UNEXPLAINED,
        NOT_ESTABLISHED,
        UNKNOWN
    }

    /** A dimension that could not be compared: no usual behaviour, or no value of the request. */
    public static Deviation notCompared(DeviationDimension dimension, String current) {
        return notCompared(dimension, current, null);
    }

    /** A dimension that could not be compared, and why (W5-10 D1). */
    public static Deviation notCompared(DeviationDimension dimension, String current, String reason) {
        return new Deviation(dimension, current, false, false, null, null, null, Explanation.UNKNOWN, null, null,
                reason);
    }

    /** The comparison as the prompt states it: {@code time 03 seen 0 of 25 (unexplained)}. */
    public String describe() {
        return describe(null, null);
    }

    /**
     * The comparison with how the value was seen over days, its first and last time, or that it was never seen (W5-10
     * D1~D3): {@code time 03 seen 0 of 17 on 0 of 5 days, not in the window, last 09-20 Sun (17 days before this
     * request) (unexplained)}. The days and times need the event clock; without it they are left out.
     */
    public String describe(Instant requestAt, ZoneId zone) {
        StringBuilder text = new StringBuilder(dimension.label());
        if (current != null) {
            text.append(' ').append(current);
        }
        // A login that holds a usual login and more names the usual login it holds (P5-변경-17).
        boolean heldLogin = dimension == DeviationDimension.LOGIN_METHOD && usual != null;
        if (heldLogin) {
            text.append(" (holds the usual ").append(usual).append(')');
        }
        if (seen != null && of != null) {
            text.append(" seen ").append(seen).append(" of ").append(of);
            if (observed != null && zone != null) {
                text.append(" on ").append(observed.days()).append(" of ").append(observed.ofDays()).append(" days");
                if (observed.seen() > 0 && observed.firstMs() != null && observed.lastMs() != null) {
                    text.append(", first ").append(date(observed.firstMs(), requestAt, zone))
                            .append(", last ").append(date(observed.lastMs(), requestAt, zone));
                }
                else if (observed.seen() == 0 && observed.retainedLastMs() != null) {
                    text.append(", not in the window, last ").append(date(observed.retainedLastMs(), requestAt, zone));
                }
                else if (observed.seen() == 0) {
                    text.append(", first time");
                }
            }
        }
        if (usual != null && !heldLogin) {
            text.append(", usual ").append(usual);
        }
        if (explanation != null) {
            text.append(" (").append(switch (explanation) {
                case EXPLAINED -> "explained by " + explainedBy;
                case UNEXPLAINED -> "unexplained";
                case NOT_ESTABLISHED -> "baseline not established";
                case UNKNOWN -> "unknown: no usual behaviour to compare with";
            }).append(')');
        }
        return text.toString();
    }

    /** A date of the event clock with how far it is from the request (W3-13): {@code 09-20 Sun (17 days before ...)}. */
    private static String date(long epochMs, Instant requestAt, ZoneId zone) {
        LocalDateTime at = LocalDateTime.ofInstant(Instant.ofEpochMilli(epochMs), zone);
        String day = String.format(Locale.ROOT, "%02d-%02d %s", at.getMonthValue(), at.getDayOfMonth(),
                at.getDayOfWeek().getDisplayName(TextStyle.SHORT, Locale.ROOT));
        String relative = requestAt != null ? RelativeTime.of(Instant.ofEpochMilli(epochMs), requestAt) : null;
        return relative != null ? day + " (" + relative + ")" : day;
    }
}
