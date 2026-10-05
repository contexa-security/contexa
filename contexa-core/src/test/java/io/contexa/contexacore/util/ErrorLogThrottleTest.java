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
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.contexa.contexacore.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

class ErrorLogThrottleTest {

    @Test
    @DisplayName("first occurrence is logged and later ones only once per interval with the skipped count")
    void logsFirstOccurrenceThenOncePerInterval() {
        AtomicLong now = new AtomicLong(1_000L);
        ErrorLogThrottle throttle = new ErrorLogThrottle(Duration.ofSeconds(60), now::get);

        assertThat(throttle.tryAcquire()).isZero();
        now.addAndGet(1_000L);
        assertThat(throttle.tryAcquire()).isEqualTo(ErrorLogThrottle.SUPPRESSED);
        now.addAndGet(1_000L);
        assertThat(throttle.tryAcquire()).isEqualTo(ErrorLogThrottle.SUPPRESSED);

        now.addAndGet(60_000L);
        assertThat(throttle.tryAcquire()).isEqualTo(2L);
        assertThat(throttle.tryAcquire()).isEqualTo(ErrorLogThrottle.SUPPRESSED);
    }
}
