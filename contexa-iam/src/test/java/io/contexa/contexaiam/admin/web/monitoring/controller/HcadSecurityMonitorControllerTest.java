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

import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.HcadSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.CountBreakdown;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.HcadEvaluationExplanation;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.LlmDecisionExplanation;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.Qualification;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.RequestExplanation;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.ScoreExplanation;
import io.contexa.contexaiam.admin.web.monitoring.service.HcadMonitoringService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

class HcadSecurityMonitorControllerTest {

    @Test
    @DisplayName("AI monitor HCAD page should use the existing HCAD view")
    void page_shouldServeAiMonitorHcadAlias() throws Exception {
        HcadMonitoringService service = mock(HcadMonitoringService.class);
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new HcadSecurityMonitorController(service)).build();

        mvc.perform(get("/contexa/admin/ai-monitor/hcad").param("period", "week"))
                .andExpect(status().isOk())
                .andExpect(view().name("contexa/admin/security-monitor-hcad"));
    }

    @Test
    @DisplayName("AI monitor HCAD API should return the same summary payload as the legacy API")
    void summary_shouldExposeAiMonitorAlias() throws Exception {
        HcadMonitoringService service = mock(HcadMonitoringService.class);
        when(service.summarize("week")).thenReturn(summary("week"));
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new HcadSecurityMonitorController(service)).build();

        mvc.perform(get("/contexa/admin/api/ai-monitor/hcad").param("period", "week"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.period").value("week"))
                .andExpect(jsonPath("$.candidateCount").value(12))
                .andExpect(jsonPath("$.currentMode").value("SHADOW"));

        mvc.perform(get("/contexa/admin/api/security-monitor/hcad/summary").param("period", "week"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.period").value("week"))
                .andExpect(jsonPath("$.candidateCount").value(12))
                .andExpect(jsonPath("$.currentMode").value("SHADOW"));
    }

    @Test
    @DisplayName("HCAD explanation API should expose persisted explanation sections")
    void explanation_shouldExposeEvaluationExplanation() throws Exception {
        HcadMonitoringService service = mock(HcadMonitoringService.class);
        when(service.explainEvaluation("eval-1")).thenReturn(explanation());
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new HcadSecurityMonitorController(service)).build();

        mvc.perform(get("/contexa/admin/api/ai-monitor/hcad/evaluations/eval-1/explanation"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.evaluationId").value("eval-1"))
                .andExpect(jsonPath("$.request.requestId").value("req-1"))
                .andExpect(jsonPath("$.score.finalScore").value(85))
                .andExpect(jsonPath("$.scoreBreakdown.scoreFormula").value("structured+semantic-normal"))
                .andExpect(jsonPath("$.signalExplanations[0].signal").value("REQUEST_BURST"))
                .andExpect(jsonPath("$.trigger.triggerDecisionReason").value("TRIGGER_PUBLISHED"))
                .andExpect(jsonPath("$.ignoredInputs[0]").value("X-Contexa-Resource-Sensitivity"));
    }

    private HcadSummary summary(String period) {
        return new HcadSummary(
                period,
                "2026-06-19T00:00:00",
                "2026-06-20T00:00:00",
                "2026-06-20T00:00:01",
                null,
                "SHADOW",
                12L,
                30L,
                3L,
                4L,
                8L,
                0.25d,
                2L,
                1L,
                0L,
                9L,
                0L,
                4L,
                1L,
                0L,
                0.66d,
                0.0d,
                15.0d,
                1L,
                0.01d,
                0.04d,
                new Qualification(0.8d, 0.9d, 0.95d, 100, 0.01d),
                "KEEP_SHADOW",
                List.of(),
                List.of(),
                List.of(new CountBreakdown("20", 12L)),
                List.of(new CountBreakdown("LOW", 12L)),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of()
        );
    }

    private HcadEvaluationExplanation explanation() {
        return new HcadEvaluationExplanation(
                "eval-1",
                new RequestExplanation(
                        "req-1",
                        "event-1",
                        "corr-1",
                        null,
                        "admin",
                        "actor-1",
                        "ctx-1",
                        "window-1",
                        "GET",
                        "/contexa/admin/dashboard",
                        "/contexa/admin/dashboard",
                        "admin.dashboard",
                        "ENFORCE",
                        "2026-06-24T10:00:00",
                        "2026-06-24T10:00:01",
                        "2026-06-24T10:00:05"),
                new ScoreExplanation(
                        85,
                        "REDLINE",
                        true,
                        true,
                        false,
                        0,
                        null,
                        "TRIGGER_PUBLISHED",
                        "TP"),
                Map.of("scoreFormula", "structured+semantic-normal"),
                List.of(Map.of("signal", "REQUEST_BURST")),
                Map.of("userId", "admin"),
                Map.of("available", true),
                Map.of("cacheStatus", "FRESH"),
                Map.of("semanticCacheAgeSeconds", 12),
                Map.of("triggerDecisionReason", "TRIGGER_PUBLISHED"),
                Map.of("userId", "TRUSTED_SERVER"),
                Map.of("promptContextContractVersion", "v1"),
                List.of("X-Contexa-Resource-Sensitivity"),
                new LlmDecisionExplanation(
                        "CHALLENGE",
                        "CHALLENGE",
                        0.82d,
                        0.91d,
                        4512L,
                        false,
                        false,
                        null,
                        null,
                        "summary",
                        "hash"));
    }
}
