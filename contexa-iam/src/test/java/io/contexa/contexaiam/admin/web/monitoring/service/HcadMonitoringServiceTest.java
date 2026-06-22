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
package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexacore.repository.HcadDetectionEvaluationRepository;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.HcadSummary;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.data.Offset.offset;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HcadMonitoringServiceTest {

    @Test
    @DisplayName("summary should calculate precision and enforce recommendation from qualification settings")
    void summarize_shouldCalculatePrecisionAndRecommendation() {
        HcadDetectionEvaluationRepository repository = mock(HcadDetectionEvaluationRepository.class);
        when(repository.countMonitorableByCreatedAtBetween(any(LocalDateTime.class), any(LocalDateTime.class))).thenReturn(120L);
        when(repository.sumMonitorableRequestCountBetween(any(), any())).thenReturn(240L);
        when(repository.countMonitorableByTriggeredLlmTrueAndCreatedAtBetween(any(), any())).thenReturn(100L);
        when(repository.sumMonitorableDuplicateSuppressedCountBetween(any(), any())).thenReturn(7L);
        when(repository.countMonitorableByEligibleTrueAndCreatedAtBetween(any(), any())).thenReturn(100L);
        when(repository.countMonitorableByEligibleFalseAndCreatedAtBetween(any(), any())).thenReturn(20L);
        when(repository.sumMonitorableNegativeCacheHitCountBetween(any(), any())).thenReturn(3L);
        when(repository.countMonitorableEscalationBetween(any(), any())).thenReturn(9L);
        when(repository.countMonitorableComparableByOutcomeClassAndCreatedAtBetween(eq("TP"), any(), any())).thenReturn(95L);
        when(repository.countMonitorableComparableByOutcomeClassAndCreatedAtBetween(eq("FP"), any(), any())).thenReturn(5L);
        when(repository.countMonitorableComparableByOutcomeClassAndCreatedAtBetween(eq("FN"), any(), any())).thenReturn(1L);
        when(repository.countMonitorableComparableByOutcomeClassAndCreatedAtBetween(eq("TN"), any(), any())).thenReturn(2L);
        when(repository.countMonitorableComparableByOutcomeClassAndCreatedAtBetween(eq("UNKNOWN"), any(), any())).thenReturn(17L);
        when(repository.averageMonitorableLlmLatencyMsBetween(any(), any())).thenReturn(42.5d);
        when(repository.countMonitorableByModeBetween(any(), any())).thenReturn(List.<Object[]>of(new Object[]{"SHADOW", 120L}));
        when(repository.countByScoreBetween(any(), any()))
                .thenReturn(List.<Object[]>of(new Object[]{"80", 70L}, new Object[]{"20", 50L}));
        when(repository.countByBandBetween(any(), any()))
                .thenReturn(List.<Object[]>of(new Object[]{"HIGH", 70L}, new Object[]{"LOW", 50L}));
        when(repository.countByScoreBandBetween(any(), any()))
                .thenReturn(List.<Object[]>of(
                        new Object[]{"20-39", 50L, 0L, 0L, 0L, 0L, 50L},
                        new Object[]{"80-100", 0L, 0L, 70L, 0L, 0L, 70L}));
        when(repository.aggregateBySignalBetween(any(), any(), anyInt()))
                .thenReturn(List.<Object[]>of(new Object[]{"REQUEST_BURST", 100L, 95L, 5L, 0L}));
        when(repository.aggregateByAnchorSignalBetween(any(), any(), anyInt()))
                .thenReturn(List.<Object[]>of(new Object[]{"IMPOSSIBLE_TRAVEL", 9L, 8L, 1L, 0L}));
        when(repository.aggregateByCorroboratingSignalBetween(any(), any(), anyInt()))
                .thenReturn(List.<Object[]>of(new Object[]{"PREVIOUS_PATH_JUMP", 50L, 40L, 4L, 6L}));
        when(repository.aggregateByResourceBetween(any(), any(), anyInt()))
                .thenReturn(List.<Object[]>of(new Object[]{"/admin/reports", "GET", 100L, 95L, 5L, 7L}));
        when(repository.aggregateByUserSessionBetween(any(), any(), anyInt()))
                .thenReturn(List.<Object[]>of(new Object[]{"alice", "ctx-1", 12L, 10L, 2L, 9L, 1L, 2L}));
        when(repository.findTop50MonitorableByCreatedAtBetweenOrderByCreatedAtDesc(any(), any())).thenReturn(List.of());
        when(repository.findTop25MonitorableByOutcomeClassAndCreatedAtBetweenOrderByCreatedAtDesc(eq("UNKNOWN"), any(), any())).thenReturn(List.of());

        HcadProperties properties = new HcadProperties();
        properties.getPreTrigger().getQualification().setEstimatedLlmCallCostUsd(0.02d);
        HcadMonitoringService service = new HcadMonitoringService(repository, properties);

        HcadSummary summary = service.summarize("week");

        assertThat(summary.period()).isEqualTo("week");
        assertThat(summary.currentMode()).isEqualTo("SHADOW");
        assertThat(summary.candidateCount()).isEqualTo(120L);
        assertThat(summary.observedRequestCount()).isEqualTo(240L);
        assertThat(summary.eligibleCount()).isEqualTo(100L);
        assertThat(summary.notEligibleCount()).isEqualTo(20L);
        assertThat(summary.triggerRate()).isCloseTo(0.8333d, offset(0.0001d));
        assertThat(summary.negativeCacheHitCount()).isEqualTo(3L);
        assertThat(summary.escalationCount()).isEqualTo(9L);
        assertThat(summary.precision()).isEqualTo(0.95d);
        assertThat(summary.estimatedWastedLlmCalls()).isEqualTo(5L);
        assertThat(summary.estimatedWasteCostUsd()).isCloseTo(0.10d, offset(0.0001d));
        assertThat(summary.estimatedSavedCostUsd()).isCloseTo(0.14d, offset(0.0001d));
        assertThat(summary.recommendation()).isEqualTo("DEFAULT_ENFORCE_CANDIDATE");
        assertThat(summary.scoreDistribution()).extracting("key").containsExactly("80", "20");
        assertThat(summary.bandDistribution()).extracting("key").containsExactly("HIGH", "LOW");
        assertThat(summary.scoreBandDistribution()).extracting("scoreBucket").containsExactly("20-39", "80-100");
        assertThat(summary.anchorSignalBreakdown()).hasSize(1);
        assertThat(summary.corroboratingSignalBreakdown()).hasSize(1);
        assertThat(summary.signalBreakdown()).hasSize(1);
        assertThat(summary.resourceBreakdown()).hasSize(1);
        assertThat(summary.userSessionBreakdown()).hasSize(1);
        assertThat(summary.unknownEvaluations()).isEmpty();
        assertThat(service.exportCsv("week")).contains("currentMode").contains("DEFAULT_ENFORCE_CANDIDATE");
    }
}
