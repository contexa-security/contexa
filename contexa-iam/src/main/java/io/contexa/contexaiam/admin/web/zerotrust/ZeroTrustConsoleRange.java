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
package io.contexa.contexaiam.admin.web.zerotrust;

import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Period;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.Locale;

/**
 * The period a screen reads (console design 6.0): the last 24 hours, 7, 30 or 90 days, or the days an operator chose.
 * The hourly tables are read from the hour the period starts in, and so is the decision list (K87), so a number of a
 * screen opens the decisions it counted. A link of a screen whose period is no whole days (the adoption trial since
 * SHADOW started) names its first moment exactly, as an ISO instant in place of the first day.
 */
record ZeroTrustConsoleRange(String key, Instant from, Instant to) {

    /** The longest period an operator may choose. */
    static final int MAX_DAYS = 400;

    static ZeroTrustConsoleRange of(String period, String fromDay, String toDay, Clock clock) {
        Instant now = clock.instant();
        String key = period == null || period.isBlank() ? "week" : period.trim().toLowerCase(Locale.ROOT);
        return switch (key) {
            case "day" -> new ZeroTrustConsoleRange(key, now.minus(Duration.ofHours(24)), now);
            case "month" -> new ZeroTrustConsoleRange(key, now.minus(Duration.ofDays(30)), now);
            case "quarter" -> new ZeroTrustConsoleRange(key, now.minus(Duration.ofDays(90)), now);
            case "custom" -> custom(fromDay, toDay, clock);
            default -> new ZeroTrustConsoleRange("week", now.minus(Duration.ofDays(7)), now);
        };
    }

    private static ZeroTrustConsoleRange custom(String fromDay, String toDay, Clock clock) {
        ZoneId zone = clock.getZone();
        try {
            Instant from = moment(fromDay, zone, false);
            Instant to = toDay == null || toDay.isBlank()
                    ? LocalDate.now(clock).plusDays(1).atStartOfDay(zone).toInstant() : moment(toDay, zone, true);
            if (!to.isAfter(from)) {
                throw new IllegalArgumentException("The period ends before it starts");
            }
            LocalDate first = LocalDate.ofInstant(from, zone);
            LocalDate last = LocalDate.ofInstant(to.minusNanos(1), zone);
            if (ChronoUnit.DAYS.between(first, last) >= MAX_DAYS) {
                throw new IllegalArgumentException("The period is longer than " + MAX_DAYS + " days");
            }
            return new ZeroTrustConsoleRange("custom", from, to);
        } catch (DateTimeParseException | NullPointerException unreadable) {
            throw new IllegalArgumentException("A custom period needs its first day as yyyy-MM-dd");
        }
    }

    /**
     * A day of the address (yyyy-MM-dd): its start, or the start of the next day for the last day; or an exact moment a
     * screen's link names (an ISO instant).
     */
    private static Instant moment(String text, ZoneId zone, boolean last) {
        if (text.indexOf('T') >= 0) {
            return Instant.parse(text);
        }
        LocalDate day = LocalDate.parse(text);
        return (last ? day.plusDays(1) : day).atStartOfDay(zone).toInstant();
    }

    Timestamp fromTimestamp() {
        return Timestamp.from(from);
    }

    /** The start of the hour the period starts in: the hourly tables count whole hours. */
    Timestamp fromHour() {
        return Timestamp.from(from.truncatedTo(ChronoUnit.HOURS));
    }

    Timestamp toTimestamp() {
        return Timestamp.from(to);
    }

    /** The weeks the period spans, for the per-week numbers; never less than a day's share of a week. */
    double weeks() {
        return Math.max(1.0 / 7.0, Duration.between(from, to).toMinutes() / (7.0 * 24 * 60));
    }

    long minutes() {
        return Math.max(1, Duration.between(from, to).toMinutes());
    }

    long days() {
        return Math.max(1, Duration.between(from, to).toDays());
    }

    Period period() {
        return new Period(key, from.toString(), to.toString());
    }
}
