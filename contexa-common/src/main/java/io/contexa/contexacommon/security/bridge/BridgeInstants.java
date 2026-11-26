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
package io.contexa.contexacommon.security.bridge;

import org.springframework.lang.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Date;
import java.util.Map;

/**
 * The one reading of a time the bridge takes from the application, whichever way it came: the security context, the
 * session, a request attribute, a header, a token claim or an explicit handoff. Each way read times its own way before:
 * a handoff and a request attribute read every number as milliseconds (seconds since the epoch became 1970), a token
 * read every number as seconds, and a header read no digits at all.
 * <p>
 * A time that already happened, such as when the user authenticated, cannot lie ahead of this server's clock by more
 * than the clocks differ. One that does (digits of a legacy date such as {@code yyyyMMddHHmmss}, read as milliseconds,
 * lie in the 27th century) is not used for a decision: the stamp leaves the time out, keeps what it ignored apart, and
 * the request goes on.
 */
public final class BridgeInstants {

    /**
     * How far ahead of this server's clock a time that already happened may lie, since the clocks of the application,
     * its identity provider and Contexa differ. It is the clock skew Spring Security's {@code JwtTimestampValidator}
     * allows by default.
     */
    public static final Duration CLOCK_SKEW = Duration.ofSeconds(60);

    /** The stamp attribute that keeps an authentication time the stamp ignored because it lay in the future. */
    public static final String IGNORED_FUTURE_AUTHENTICATION_TIME = "ignoredFutureAuthenticationTime";

    /** The attribute of a stamp that holds the authentication time the application stated. */
    private static final String AUTHENTICATION_TIME = "authenticationTime";

    /** Numbers below this are seconds since the epoch (up to the year 5138), numbers from it are milliseconds. */
    private static final long MILLISECONDS_FROM = 100_000_000_000L;

    private BridgeInstants() {
    }

    /**
     * The instant a value states: an {@link Instant}, a {@link Date}, a number or a text of digits (seconds since the
     * epoch, or milliseconds from 100,000,000,000 on), or ISO-8601 text of an instant ({@code Z} or an offset).
     *
     * @return the instant, or {@code null} when the value states none
     */
    @Nullable
    public static Instant parse(@Nullable Object value) {
        if (value instanceof Instant instant) {
            return instant;
        }
        if (value instanceof Date date) {
            return date.toInstant();
        }
        if (value instanceof Number number) {
            return fromEpoch(number.longValue());
        }
        if (!(value instanceof CharSequence characters)) {
            return null;
        }
        String text = characters.toString().trim();
        if (text.isEmpty()) {
            return null;
        }
        if (text.chars().allMatch(Character::isDigit)) {
            try {
                return fromEpoch(Long.parseLong(text));
            } catch (NumberFormatException tooLong) {
                return null;
            }
        }
        try {
            return Instant.parse(text);
        } catch (DateTimeParseException notAnInstant) {
            return null;
        }
    }

    /** Whether a time that already happened lies ahead of the moment by more than the clocks differ. */
    public static boolean isFuture(@Nullable Instant happenedAt, Instant now) {
        return happenedAt != null && happenedAt.isAfter(now.plus(CLOCK_SKEW));
    }

    /** As {@link #isFuture(Instant, Instant)}, against this server's clock. */
    public static boolean isFuture(@Nullable Instant happenedAt) {
        return isFuture(happenedAt, Instant.now());
    }

    /**
     * The authentication time a stamp may use. One ahead of this server's clock is left out: the attributes of the stamp
     * lose the stated time and keep the ignored one apart, under {@link #IGNORED_FUTURE_AUTHENTICATION_TIME}.
     *
     * @param read       the authentication time read for the stamp
     * @param attributes the stamp's attributes, changed when the time is left out
     * @return the time, or {@code null} when none was read or it lay in the future
     */
    @Nullable
    public static Instant authenticationTime(@Nullable Instant read, Map<String, Object> attributes) {
        if (!isFuture(read)) {
            return read;
        }
        attributes.remove(AUTHENTICATION_TIME);
        attributes.put(IGNORED_FUTURE_AUTHENTICATION_TIME, read.toString());
        return null;
    }

    private static Instant fromEpoch(long value) {
        if (Math.abs(value) < MILLISECONDS_FROM) {
            return Instant.ofEpochSecond(value);
        }
        return Instant.ofEpochMilli(value);
    }
}
