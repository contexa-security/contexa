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
        when(repository.countByCreatedAtBetween(any(LocalDateTime.class), any(LocalDateTime.class))).thenReturn(120L);
        when(repository.sumRequestCountBetween(any(), any())).thenReturn(240L);
        when(repository.countByTriggeredLlmTrueAndCreatedAtBetween(any(), any())).thenReturn(100L);
        when(repository.sumDuplicateSuppressedCountBetween(any(), any())).thenReturn(7L);
        when(repository.countByOutcomeClassAndCreatedAtBetween(eq("TP"), any(), any())).thenReturn(95L);
        when(repository.countByOutcomeClassAndCreatedAtBetween(eq("FP"), any(), any())).thenReturn(5L);
        when(repository.countByOutcomeClassAndCreatedAtBetween(eq("FN"), any(), any())).thenReturn(1L);
        when(repository.countByOutcomeClassAndCreatedAtBetween(eq("TN"), any(), any())).thenReturn(2L);
        when(repository.countByOutcomeClassAndCreatedAtBetween(eq("UNKNOWN"), any(), any())).thenReturn(17L);
        when(repository.averageLlmLatencyMsBetween(any(), any())).thenReturn(42.5d);
        when(repository.countByModeBetween(any(), any())).thenReturn(List.<Object[]>of(new Object[]{"SHADOW", 120L}));
        when(repository.aggregateBySignalBetween(any(), any(), anyInt()))
                .thenReturn(List.<Object[]>of(new Object[]{"REQUEST_BURST", 100L, 95L, 5L, 0L}));
        when(repository.aggregateByResourceBetween(any(), any(), anyInt()))
                .thenReturn(List.<Object[]>of(new Object[]{"/admin/reports", "GET", 100L, 95L, 5L, 7L}));
        when(repository.aggregateByUserSessionBetween(any(), any(), anyInt()))
                .thenReturn(List.<Object[]>of(new Object[]{"alice", "ctx-1", 12L, 10L, 2L, 9L, 1L, 2L}));
        when(repository.findTop50ByCreatedAtBetweenOrderByCreatedAtDesc(any(), any())).thenReturn(List.of());
        when(repository.findTop25ByOutcomeClassAndCreatedAtBetweenOrderByCreatedAtDesc(eq("UNKNOWN"), any(), any())).thenReturn(List.of());

        HcadProperties properties = new HcadProperties();
        properties.getPreTrigger().getQualification().setEstimatedLlmCallCostUsd(0.02d);
        HcadMonitoringService service = new HcadMonitoringService(repository, properties);

        HcadSummary summary = service.summarize("week");

        assertThat(summary.period()).isEqualTo("week");
        assertThat(summary.currentMode()).isEqualTo("SHADOW");
        assertThat(summary.candidateCount()).isEqualTo(120L);
        assertThat(summary.observedRequestCount()).isEqualTo(240L);
        assertThat(summary.precision()).isEqualTo(0.95d);
        assertThat(summary.estimatedWastedLlmCalls()).isEqualTo(5L);
        assertThat(summary.estimatedWasteCostUsd()).isCloseTo(0.10d, offset(0.0001d));
        assertThat(summary.recommendation()).isEqualTo("DEFAULT_ENFORCE_CANDIDATE");
        assertThat(summary.signalBreakdown()).hasSize(1);
        assertThat(summary.resourceBreakdown()).hasSize(1);
        assertThat(summary.userSessionBreakdown()).hasSize(1);
        assertThat(summary.unknownEvaluations()).isEmpty();
        assertThat(service.exportCsv("week")).contains("currentMode").contains("DEFAULT_ENFORCE_CANDIDATE");
    }
}
