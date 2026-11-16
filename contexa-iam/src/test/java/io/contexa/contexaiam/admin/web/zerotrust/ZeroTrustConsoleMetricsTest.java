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

import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.MetricValue;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.RangedMetric;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;

/** Console design 5: a metric's value, its numerator and denominator, its range and its reason when it has none. */
class ZeroTrustConsoleMetricsTest {

    private final ZeroTrustConsoleMetrics metrics = new ZeroTrustConsoleMetrics(null, Locale.ENGLISH);

    @Test
    void aRatioKeepsItsNumeratorAndDenominatorAndAnEmptyOneHasNoValue() {
        MetricValue ratio = metrics.ratio("stopped", 3, 12, ZeroTrustConsoleMetrics.NO_DECISIONS);
        MetricValue empty = metrics.ratio("stopped", 0, 0, ZeroTrustConsoleMetrics.NO_DECISIONS);

        assertThat(ratio.value()).isEqualTo(0.25);
        assertThat(ratio.numerator()).isEqualTo(3);
        assertThat(ratio.denominator()).isEqualTo(12);
        assertThat(ratio.noDataReason()).isNull();
        assertThat(empty.value()).as("never 0 for nothing").isNull();
        assertThat(empty.noDataReason()).isEqualTo(ZeroTrustConsoleMetrics.NO_DECISIONS);
    }

    /** The Wilson interval: 47 of 50 is 94% with 84% to 98% around it (console design 6.3). */
    @Test
    void theRangeIsTheWilsonInterval() {
        RangedMetric ranged = metrics.ranged("reviewValid", 47, 50, null);

        assertThat(ranged.metric().value()).isEqualTo(0.94);
        assertThat(ranged.lower95()).isCloseTo(0.838, within(0.005));
        assertThat(ranged.upper95()).isCloseTo(0.979, within(0.005));
        assertThat(ranged.sample()).isEqualTo(50);
        assertThat(ZeroTrustConsoleMetrics.wilson(0, 0)).isNull();
        double[] none = ZeroTrustConsoleMetrics.wilson(0, 10);
        assertThat(none[0]).isZero();
        assertThat(none[1]).isBetween(0.2, 0.35);
    }

    @Test
    void aPercentileIsReadInsideItsBucket() {
        long[] buckets = new long[10];
        buckets[3] = 50;
        buckets[4] = 50;

        assertThat(ZeroTrustConsoleMetrics.percentile(buckets, 0.5)).isEqualTo(1000L);
        assertThat(ZeroTrustConsoleMetrics.percentile(buckets, 0.95)).isEqualTo(1900L);
        assertThat(ZeroTrustConsoleMetrics.percentile(new long[10], 0.5)).isNull();
        long[] slow = new long[10];
        slow[9] = 4;
        assertThat(ZeroTrustConsoleMetrics.percentile(slow, 0.95)).as("past the last bound").isEqualTo(60_000L);
        assertThat(ZeroTrustConsoleMetrics.percentileOf(List.of(0.0, 0.0, 1.0, 3.0), 0.5)).isEqualTo(0.0);
        assertThat(ZeroTrustConsoleMetrics.percentileOf(List.of(0.0, 0.0, 1.0, 3.0), 0.95)).isEqualTo(3.0);
        assertThat(ZeroTrustConsoleMetrics.percentileOf(List.of(), 0.5)).isNull();
    }

    @Test
    void sharesAreLargestFirstWithTheirPartOfTheWhole() {
        assertThat(ZeroTrustConsoleMetrics.shares(Map.of("A", 1L, "B", 3L)))
                .extracting(share -> share.key() + "=" + share.ratio()).containsExactly("B=0.75", "A=0.25");
        assertThat(ZeroTrustConsoleMetrics.sharesOf(Map.of("A", 0L), 0)).first()
                .satisfies(share -> assertThat(share.ratio()).isNull());
    }

    @Test
    void aPeriodIsTheLastDayWeekMonthOrQuarterOrTheDaysChosen() {
        Instant now = Instant.parse("2026-11-15T10:30:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);

        assertThat(ZeroTrustConsoleRange.of(null, null, null, clock).key()).isEqualTo("week");
        assertThat(ZeroTrustConsoleRange.of("day", null, null, clock).from()).isEqualTo(now.minus(Duration.ofHours(24)));
        assertThat(ZeroTrustConsoleRange.of("quarter", null, null, clock).days()).isEqualTo(90);
        assertThat(ZeroTrustConsoleRange.of("nonsense", null, null, clock).key()).isEqualTo("week");
        ZeroTrustConsoleRange custom = ZeroTrustConsoleRange.of("custom", "2026-11-01", "2026-11-14", clock);
        assertThat(custom.from()).isEqualTo(Instant.parse("2026-11-01T00:00:00Z"));
        assertThat(custom.to()).isEqualTo(Instant.parse("2026-11-15T00:00:00Z"));
        assertThat(ZeroTrustConsoleRange.of("week", null, null, clock).fromHour().toInstant())
                .isEqualTo(Instant.parse("2026-11-08T10:00:00Z"));
        assertThatThrownBy(() -> ZeroTrustConsoleRange.of("custom", "2026-11-14", "2026-11-01", clock))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ZeroTrustConsoleRange.of("custom", "yesterday", null, clock))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ZeroTrustConsoleRange.of("custom", "2025-01-01", "2026-11-14", clock))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
