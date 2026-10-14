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

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.regex.Pattern;

/**
 * How far a time of the event clock is from the request, in one form (W3-13, dictionary 1.5): whole minutes under an
 * hour, whole hours under two days, whole days beyond, then {@code before this request} or {@code after this request}.
 * A time in the request's own minute is {@code 0 min before this request}.
 */
public final class RelativeTime {

    private static final long MINUTES_PER_HOUR = 60L;
    private static final long HOURS_IN_DAYS = 48L;

    private RelativeTime() {
    }

    /** The distance of the time from the request ({@code 3 min before this request}), or null without either. */
    public static String of(Instant time, Instant request) {
        if (time == null || request == null) {
            return null;
        }
        return describe(Duration.between(time, request));
    }

    /** The distance of a wall-clock time of the event clock from the request's, or null without either. */
    public static String of(LocalDateTime time, LocalDateTime request) {
        if (time == null || request == null) {
            return null;
        }
        return describe(Duration.between(time, request));
    }

    /**
     * Where the ends of a window are from the request ({@code from 24 h before to 2 days after this request}); a window
     * open at one end names the other only. Null without the request or without both ends.
     */
    public static String window(Instant from, Instant until, Instant request) {
        if (request == null || (from == null && until == null)) {
            return null;
        }
        if (from == null) {
            return "until " + of(until, request);
        }
        if (until == null) {
            return "from " + of(from, request);
        }
        return "from " + amount(Duration.between(from, request)) + " " + direction(Duration.between(from, request))
                + " to " + of(until, request);
    }

    /** A distance as {@link #of} writes it, with its amount, unit and direction (R1b-3: shared with the inspector). */
    public static final Pattern DISTANCE = Pattern.compile("(\\d+) (min|h|days) (before|after) this request");

    private static String describe(Duration beforeRequest) {
        return amount(beforeRequest) + " " + direction(beforeRequest) + " this request";
    }

    private static String direction(Duration beforeRequest) {
        return beforeRequest.isNegative() ? "after" : "before";
    }

    private static String amount(Duration beforeRequest) {
        long minutes = beforeRequest.abs().toMinutes();
        if (minutes < MINUTES_PER_HOUR) {
            return minutes + " min";
        }
        long hours = minutes / MINUTES_PER_HOUR;
        if (hours < HOURS_IN_DAYS) {
            return hours + " h";
        }
        return (hours / 24L) + " days";
    }
}
