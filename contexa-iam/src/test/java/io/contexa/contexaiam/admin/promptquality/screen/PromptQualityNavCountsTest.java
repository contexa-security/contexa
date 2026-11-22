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
package io.contexa.contexaiam.admin.promptquality.screen;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityScreens.Count;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Quality plan 3.8: the counts of the menu bar come from the services of the screens, for the scope of the page and
 * the security decision; both kinds of measurement are one count; the count of sealed decisions covers the period the
 * sealed evidence opens with and is read again once a minute at most; a count whose service is absent, or that cannot
 * be read, is no count.
 */
class PromptQualityNavCountsTest {

    private static final String PROMPT = "cortex.security-decision";
    private static final Instant NOW = Instant.parse("2026-11-22T12:00:00Z");

    private final PromptQualityCases cases = mock(PromptQualityCases.class);
    private final PromptQualityMeasurements measurements = mock(PromptQualityMeasurements.class);
    private final PromptVersionTrials trials = mock(PromptVersionTrials.class);
    private final PromptVersionService versions = mock(PromptVersionService.class);
    private final SealedEvidencePackageRepository sealed = mock(SealedEvidencePackageRepository.class);
    private final AtomicReference<Instant> now = new AtomicReference<>(NOW);
    private final Clock clock = new Clock() {
        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    };

    @Test
    void eachCountComesFromItsServiceForTheScopeAndTheSecurityDecision() {
        when(cases.count("tenant-a", PROMPT)).thenReturn(76L);
        when(measurements.count("tenant-a", PROMPT)).thenReturn(4L);
        when(trials.count("tenant-a", PROMPT)).thenReturn(2L);
        when(versions.count("tenant-a", PROMPT)).thenReturn(3L);
        when(sealed.countCapturedSince(NOW.minus(Duration.ofDays(7)))).thenReturn(1_284L);
        PromptQualityNavCounts counts = all();

        assertThat(counts.count(Count.CASES, "tenant-a")).isEqualTo(76L);
        assertThat(counts.count(Count.MEASUREMENTS, "tenant-a")).isEqualTo(6L);
        assertThat(counts.count(Count.VERSIONS, "tenant-a")).isEqualTo(3L);
        assertThat(counts.count(Count.SEALED, "tenant-a")).isEqualTo(1_284L);
        assertThat(PromptQualityNavCounts.PROMPT).isEqualTo(PROMPT);
    }

    @Test
    void theSealedDecisionsAreCountedAgainOnceAMinuteAtMost() {
        when(sealed.countCapturedSince(any())).thenReturn(10L, 11L);
        PromptQualityNavCounts counts = all();

        assertThat(counts.count(Count.SEALED, null)).isEqualTo(10L);
        now.set(NOW.plusSeconds(59));
        assertThat(counts.count(Count.SEALED, "tenant-b")).isEqualTo(10L);
        verify(sealed, times(1)).countCapturedSince(any());

        now.set(NOW.plus(PromptQualityNavCounts.SEALED_KEPT));
        assertThat(counts.count(Count.SEALED, null)).isEqualTo(11L);
        verify(sealed).countCapturedSince(NOW.plus(PromptQualityNavCounts.SEALED_KEPT).minus(Duration.ofDays(7)));
    }

    @Test
    void aCountWhoseServiceIsAbsentIsNoCount() {
        PromptQualityNavCounts none = new PromptQualityNavCounts(() -> null, () -> null, () -> null, () -> null,
                () -> null, clock);
        for (Count count : Count.values()) {
            assertThat(none.count(count, null)).as(count.name()).isNull();
        }
        // Either kind of measurement alone is still a count.
        when(trials.count(null, PROMPT)).thenReturn(2L);
        assertThat(new PromptQualityNavCounts(() -> null, () -> null, () -> trials, () -> null, () -> null, clock)
                .count(Count.MEASUREMENTS, null)).isEqualTo(2L);
    }

    @Test
    void aCountThatCannotBeReadIsNoCountAndTheOthersStillAre() {
        when(cases.count(null, PROMPT)).thenThrow(new DataAccessResourceFailureException("database down"));
        when(versions.count(null, PROMPT)).thenReturn(1L);
        PromptQualityNavCounts counts = all();

        assertThat(counts.count(Count.CASES, null)).isNull();
        assertThat(counts.count(Count.VERSIONS, null)).isEqualTo(1L);
    }

    private PromptQualityNavCounts all() {
        return new PromptQualityNavCounts(() -> cases, () -> measurements, () -> trials, () -> versions, () -> sealed,
                clock);
    }
}
