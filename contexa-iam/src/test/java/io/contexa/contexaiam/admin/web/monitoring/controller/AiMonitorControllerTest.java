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
package io.contexa.contexaiam.admin.web.monitoring.controller;

import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.CorrelationSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.CorrelationMatrixRow;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.FailureSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.LlmDecisionSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.NamedCount;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.OperationsSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.OverviewSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.RecentCorrelation;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.ReadinessSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.CountBreakdown;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.HcadSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.Qualification;
import io.contexa.contexaiam.admin.web.monitoring.service.AiSecurityDecisionMonitoringService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Locale;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AiMonitorControllerTest {

    @Test
    @DisplayName("Overview API should expose integrated HCAD, LLM and correlation summary")
    void overview_shouldExposeIntegratedSummary() throws Exception {
        AiSecurityDecisionMonitoringService service = mock(AiSecurityDecisionMonitoringService.class);
        when(service.overview("day")).thenReturn(summary());
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new AiMonitorController(service)).build();

        mvc.perform(get("/contexa/admin/api/ai-monitor/overview").param("period", "day"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.period").value("day"))
                .andExpect(jsonPath("$.hcad.candidateCount").value(10))
                .andExpect(jsonPath("$.llm.totalDecisionCount").value(7))
                .andExpect(jsonPath("$.llm.triggerSourceBreakdown[0].key").value("HCAD_PRE_TRIGGER"))
                .andExpect(jsonPath("$.llm.riskScoreDistribution[0].key").value("0.80-1.00"))
                .andExpect(jsonPath("$.correlation.truePositiveCount").value(3))
                .andExpect(jsonPath("$.correlation.matrixRows[0].key").value("HCAD_EARLY_TRIGGER"))
                .andExpect(jsonPath("$.operations.parserFailureCount").value(1))
                .andExpect(jsonPath("$.readinessRecommendation").value("KEEP_SHADOW"));
    }

    @Test
    @DisplayName("Section APIs should expose LLM, correlation, failures, readiness and CSV export")
    void sectionApis_shouldExposeDocumentedContracts() throws Exception {
        AiSecurityDecisionMonitoringService service = mock(AiSecurityDecisionMonitoringService.class);
        OverviewSummary summary = summary();
        when(service.llm("day")).thenReturn(summary.llm());
        when(service.correlation("day")).thenReturn(summary.correlation());
        when(service.failures("day")).thenReturn(new FailureSummary(
                "day",
                summary.from(),
                summary.to(),
                summary.operations(),
                List.of(new NamedCount("TIMEOUT", 1L)),
                List.of(new NamedCount("TIMEOUT", 1L)),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of()));
        when(service.readiness("day")).thenReturn(new ReadinessSummary(
                "day",
                summary.from(),
                summary.to(),
                "KEEP_SHADOW",
                100L,
                10L,
                7L,
                0.75d,
                0.1d,
                0.1d,
                0.14d,
                0.14d,
                0.0d,
                0.0d,
                0.0d,
                40.0d,
                60.0d,
                0.01d,
                0.08d));
        when(service.exportCsv("day", "overview", Locale.KOREAN)).thenReturn("\"항목\",\"값\"\n");
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new AiMonitorController(service)).build();

        mvc.perform(get("/contexa/admin/api/ai-monitor/llm").param("period", "day"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalDecisionCount").value(7));
        mvc.perform(get("/contexa/admin/api/ai-monitor/correlation").param("period", "day"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.truePositiveCount").value(3));
        mvc.perform(get("/contexa/admin/api/ai-monitor/failures").param("period", "day"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.operations.timeoutCount").value(0));
        mvc.perform(get("/contexa/admin/api/ai-monitor/readiness").param("period", "day"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.recommendation").value("KEEP_SHADOW"));
        mvc.perform(get("/contexa/admin/api/ai-monitor/export.csv")
                        .param("period", "day")
                        .param("type", "overview")
                        .locale(Locale.KOREAN))
                .andExpect(status().isOk())
                .andExpect(content().string("\"항목\",\"값\"\n"));
    }

    private OverviewSummary summary() {
        HcadSummary hcad = new HcadSummary(
                "day",
                "2026-06-19T00:00:00",
                "2026-06-20T00:00:00",
                "SHADOW",
                10L,
                20L,
                5L,
                6L,
                4L,
                0.5d,
                3L,
                1L,
                1L,
                4L,
                1L,
                8L,
                2L,
                1L,
                0.75d,
                0.1d,
                40.0d,
                1L,
                0.01d,
                0.08d,
                new Qualification(0.8d, 0.9d, 0.95d, 100, 0.01d),
                "KEEP_SHADOW",
                List.of(),
                List.of(),
                List.of(new CountBreakdown("80", 4L)),
                List.of(new CountBreakdown("HIGH", 4L)),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of());
        return new OverviewSummary(
                "day",
                "2026-06-19T00:00:00",
                "2026-06-20T00:00:00",
                hcad,
                new LlmDecisionSummary(
                        7L,
                        4L,
                        3L,
                        0L,
                        List.of(new NamedCount("HCAD_PRE_TRIGGER", 4L)),
                        List.of(new NamedCount("ALLOW", 4L)),
                        List.of(new NamedCount("ALLOW", 4L)),
                        List.of(new NamedCount("ALLOW", 4L)),
                        List.of(new NamedCount("ollama", 4L)),
                        List.of(),
                        List.of(),
                        1L,
                        0L,
                        0L,
                        0L,
                        0.14d,
                        0.0d,
                        0.0d,
                        0.0d,
                        40.0d,
                        60.0d,
                        List.of(new NamedCount("0.80-1.00", 4L)),
                        List.of(new NamedCount("0.80-1.00", 4L))),
                new CorrelationSummary(
                        3L,
                        1L,
                        1L,
                        4L,
                        1L,
                        0L,
                        List.of(),
                        List.of(),
                        List.of(new CorrelationMatrixRow("HCAD_EARLY_TRIGGER", 3L, 1L, 0L, 0L)),
                        List.of(),
                        List.of(new RecentCorrelation(
                                "corr-1",
                                "eval-1",
                                "obs-1",
                                "event-1",
                                "req-1",
                                "admin",
                                "HCAD_ONLY",
                                "TP",
                                85,
                                "HIGH",
                                true,
                                "BLOCK",
                                "BLOCK",
                                0.9d,
                                0.8d,
                                "2026-06-19T00:00:00",
                                "2026-06-19T00:00:01"))),
                new OperationsSummary(
                        40.0d,
                        1L,
                        0L,
                        0L,
                        0L,
                        1L,
                        0.01d,
                        0.08d),
                "KEEP_SHADOW");
    }
}
