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

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

/** W3-13 (dictionary 1.5): a time on the event clock says how far it is from the request, in one form. */
class RelativeTimeTest {

    private static final Instant REQUEST = Instant.parse("2026-09-30T03:17:00Z");

    @Test
    void aTimeSaysHowFarBeforeOrAfterTheRequestItIsInMinutesHoursOrDays() {
        assertThat(RelativeTime.of(REQUEST, REQUEST)).isEqualTo("0 min before this request");
        assertThat(RelativeTime.of(REQUEST.minusSeconds(59), REQUEST)).isEqualTo("0 min before this request");
        assertThat(RelativeTime.of(REQUEST.minus(Duration.ofMinutes(59)), REQUEST)).isEqualTo("59 min before this request");
        assertThat(RelativeTime.of(REQUEST.minus(Duration.ofMinutes(60)), REQUEST)).isEqualTo("1 h before this request");
        assertThat(RelativeTime.of(REQUEST.minus(Duration.ofMinutes(47 * 60 + 59)), REQUEST))
                .isEqualTo("47 h before this request");
        assertThat(RelativeTime.of(REQUEST.minus(Duration.ofHours(48)), REQUEST)).isEqualTo("2 days before this request");
        assertThat(RelativeTime.of(REQUEST.minus(Duration.ofDays(9)).minusSeconds(1), REQUEST))
                .isEqualTo("9 days before this request");
        assertThat(RelativeTime.of(REQUEST.plus(Duration.ofMinutes(20)), REQUEST)).isEqualTo("20 min after this request");
        assertThat(RelativeTime.of(REQUEST.plusSeconds(30), REQUEST)).isEqualTo("0 min after this request");
        assertThat(RelativeTime.of(REQUEST.plus(Duration.ofDays(5)).plus(Duration.ofHours(5)), REQUEST))
                .isEqualTo("5 days after this request");
    }

    @Test
    void wallClockTimesOfTheEventClockAreComparedTheSameWay() {
        LocalDateTime request = LocalDateTime.parse("2026-09-30T03:17");

        assertThat(RelativeTime.of(LocalDateTime.parse("2026-09-29T13:52"), request)).isEqualTo("13 h before this request");
        assertThat(RelativeTime.of(LocalDateTime.parse("2026-10-05T09:00"), request)).isEqualTo("5 days after this request");
    }

    @Test
    void aWindowSaysWhereItsEndsAreFromTheRequest() {
        assertThat(RelativeTime.window(REQUEST.minus(Duration.ofHours(24)), REQUEST.plus(Duration.ofHours(48)), REQUEST))
                .isEqualTo("from 24 h before to 2 days after this request");
        assertThat(RelativeTime.window(REQUEST.minus(Duration.ofHours(6)), REQUEST.minus(Duration.ofHours(2)), REQUEST))
                .isEqualTo("from 6 h before to 2 h before this request");
        assertThat(RelativeTime.window(REQUEST.minus(Duration.ofHours(6)), null, REQUEST))
                .isEqualTo("from 6 h before this request");
        assertThat(RelativeTime.window(null, REQUEST.plus(Duration.ofMinutes(5)), REQUEST))
                .isEqualTo("until 5 min after this request");
    }

    @Test
    void withoutTheRequestTimeOrTheTimeThereIsNoDistance() {
        assertThat(RelativeTime.of(REQUEST, (Instant) null)).isNull();
        assertThat(RelativeTime.of((Instant) null, REQUEST)).isNull();
        assertThat(RelativeTime.of((LocalDateTime) null, LocalDateTime.parse("2026-09-30T03:17"))).isNull();
        assertThat(RelativeTime.window(null, null, REQUEST)).isNull();
        assertThat(RelativeTime.window(REQUEST, REQUEST, null)).isNull();
    }
}
