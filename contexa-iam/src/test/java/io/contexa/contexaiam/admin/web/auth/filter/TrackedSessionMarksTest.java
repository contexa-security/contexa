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
package io.contexa.contexaiam.admin.web.auth.filter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/** The marks Contexa keeps of the sessions it tracks only spare the database, and last no longer than their interval. */
@DisplayName("Contexa 쪽 세션 표시는 확인·기록 간격 동안만 남는다")
class TrackedSessionMarksTest {

    private final SessionTrackingFilterTest.MovingClock clock = new SessionTrackingFilterTest.MovingClock();
    private final TrackedSessionMarks marks = new TrackedSessionMarks(clock);

    @Test
    @DisplayName("만료 확인 표시는 확인 간격 뒤에 정리되고 다시 확인할 때가 된다")
    void theCheckMarkGoesAfterTheCheckInterval() {
        assertThat(marks.checkDue("sid-a")).isTrue();
        assertThat(marks.checkDue("sid-a")).isFalse();

        clock.advance(TrackedSessionMarks.EXPIRY_CHECK_INTERVAL);
        marks.removeExpiredEntries();

        assertThat(marks.checkDue("sid-a")).isTrue();
    }

    @Test
    @DisplayName("활동 기록 표시는 기록 간격 뒤에 정리되고 다시 기록할 때가 된다")
    void theTrackingMarkGoesAfterTheTrackingInterval() {
        assertThat(marks.trackDue("sid-b")).isTrue();
        clock.advance(TrackedSessionMarks.TRACKING_INTERVAL.minus(Duration.ofMillis(1)));
        assertThat(marks.trackDue("sid-b")).isFalse();

        clock.advance(Duration.ofMillis(1));
        marks.removeExpiredEntries();

        assertThat(marks.trackDue("sid-b")).isTrue();
    }

    @Test
    @DisplayName("끝난 세션의 표시는 곧바로 사라진다")
    void theMarksOfASessionThatEndedGoAtOnce() {
        marks.checkDue("sid-c");
        marks.trackDue("sid-c");

        marks.forget("sid-c");

        assertThat(marks.checkDue("sid-c")).isTrue();
        assertThat(marks.trackDue("sid-c")).isTrue();
    }
}
