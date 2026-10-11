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
package io.contexa.contexacommon.domain;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

/**
 * The time zone in which security events are read as wall-clock times: their hour, minute and day of week. It is the
 * company's time zone, set once from configuration; without it the system time zone is used. Event times themselves
 * are instants and do not depend on it.
 */
public final class EventTimeZone {

    private static volatile ZoneId zone;

    private EventTimeZone() {
    }

    /** Sets the time zone; null returns to the system time zone. */
    public static void set(ZoneId timeZone) {
        zone = timeZone;
    }

    public static ZoneId get() {
        ZoneId configured = zone;
        return configured != null ? configured : ZoneId.systemDefault();
    }

    /** The instant as a wall-clock time in this time zone; null when the instant is null. */
    public static LocalDateTime toLocal(Instant instant) {
        return instant != null ? LocalDateTime.ofInstant(instant, get()) : null;
    }
}
