/*
 * Copyright 2026 The Contexa Project
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.admin.web.monitoring.controller;

import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.FailureSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.LlmDecisionSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.NamedCount;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.OperationsSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.OverviewSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.ReadinessSummary;
import io.contexa.contexaiam.admin.web.monitoring.service.AiSecurityDecisionMonitoringService;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Locale;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AiMonitorControllerTest {

    @Test
    void overviewApiExposesLlmOperationsOnly() throws Exception {
        AiSecurityDecisionMonitoringService service = mock(AiSecurityDecisionMonitoringService.class);
        when(service.overview("day")).thenReturn(summary());
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new AiMonitorController(service)).build();

        mvc.perform(get("/contexa/admin/api/ai-monitor/overview").principal(admin()).param("period", "day"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.period").value("day"))
                .andExpect(jsonPath("$.llm.totalDecisionCount").value(7))
                .andExpect(jsonPath("$.llm.protectableDecisionCount").value(7))
                .andExpect(jsonPath("$.operations.parserFailureCount").value(1))
                .andExpect(jsonPath("$.readinessRecommendation").value("KEEP_MONITORING"))
                .andExpect(jsonPath("$.hcad").doesNotExist())
                .andExpect(jsonPath("$.correlation").doesNotExist());
    }

    @Test
    void sectionApisExposeLlmFailuresReadinessAndCsv() throws Exception {
        AiSecurityDecisionMonitoringService service = mock(AiSecurityDecisionMonitoringService.class);
        OverviewSummary overview = summary();
        when(service.llm("day")).thenReturn(overview.llm());
        when(service.failures("day")).thenReturn(new FailureSummary(
                "day", overview.from(), overview.to(), overview.generatedAt(), null, null,
                overview.operations(), List.of(new NamedCount("TIMEOUT", 1L)),
                List.of(new NamedCount("TIMEOUT", 1L)), List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of()));
        when(service.readiness("day")).thenReturn(new ReadinessSummary(
                "day", overview.from(), overview.to(), overview.generatedAt(), null, null,
                "KEEP_MONITORING", 7L, 0.1d, 0.1d, 0.0d, 0.0d, 0.0d,
                40.0d, 60.0d, null, List.of(), List.of()));
        when(service.exportCsv("day", "overview", Locale.KOREAN)).thenReturn("metric,count\n");
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new AiMonitorController(service)).build();

        mvc.perform(get("/contexa/admin/api/ai-monitor/llm").principal(admin()).param("period", "day"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.totalDecisionCount").value(7));
        mvc.perform(get("/contexa/admin/api/ai-monitor/failures").principal(admin()).param("period", "day"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.operations.parserFailureCount").value(1));
        mvc.perform(get("/contexa/admin/api/ai-monitor/readiness").principal(admin()).param("period", "day"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.recommendation").value("KEEP_MONITORING"));
        mvc.perform(get("/contexa/admin/api/ai-monitor/export.csv").principal(admin())
                        .param("period", "day").param("type", "overview").locale(Locale.KOREAN))
                .andExpect(status().isOk()).andExpect(content().string("metric,count\n"));
    }

    @Test
    void removedHcadAndCorrelationApisHaveNoMapping() throws Exception {
        AiSecurityDecisionMonitoringService service = mock(AiSecurityDecisionMonitoringService.class);
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new AiMonitorController(service)).build();
        mvc.perform(get("/contexa/admin/api/ai-monitor/correlation").principal(admin()))
                .andExpect(status().isNotFound());
        mvc.perform(get("/contexa/admin/api/ai-monitor/hcad").principal(admin()))
                .andExpect(status().isNotFound());
        mvc.perform(get("/contexa/admin/api/security-monitor/hcad/summary").principal(admin()))
                .andExpect(status().isNotFound());
    }

    @Test
    void resetRequiresExplicitConfirmation() throws Exception {
        AiSecurityDecisionMonitoringService service = mock(AiSecurityDecisionMonitoringService.class);
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new AiMonitorController(service)).build();
        mvc.perform(post("/contexa/admin/api/ai-monitor/reset").principal(admin())
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void APIsRejectNonAdminUsers() throws Exception {
        AiSecurityDecisionMonitoringService service = mock(AiSecurityDecisionMonitoringService.class);
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new AiMonitorController(service)).build();
        mvc.perform(get("/contexa/admin/api/ai-monitor/session/current")
                        .principal(new TestingAuthenticationToken("user", "n/a", "ROLE_USER")))
                .andExpect(status().isForbidden());
    }

    private OverviewSummary summary() {
        LlmDecisionSummary llm = new LlmDecisionSummary(
                null, null, 7L, 7L,
                List.of(new NamedCount("PROTECTABLE", 7L)),
                List.of(new NamedCount("ALLOW", 7L)),
                List.of(new NamedCount("ALLOW", 7L)),
                List.of(new NamedCount("ALLOW", 7L)),
                List.of(new NamedCount("openai", 7L)),
                List.of(new NamedCount("gpt-5-nano", 7L)),
                List.of(new NamedCount("security-decision-v1", 7L)),
                1L, 0L, 0L, 0L,
                1.0d / 7.0d, 0.0d, 0.0d, 0.0d,
                40.0d, 60.0d,
                List.of(new NamedCount("0.80-1.00", 4L)),
                List.of(new NamedCount("0.80-1.00", 4L)));
        OperationsSummary operations = new OperationsSummary(40.0d, 1L, 0L, 0L, 0L, 0L, List.of());
        return new OverviewSummary(
                "day", "2026-06-19T00:00:00", "2026-06-20T00:00:00",
                "2026-06-20T00:00:01", null, null, llm, operations, "KEEP_MONITORING");
    }

    private TestingAuthenticationToken admin() {
        return new TestingAuthenticationToken("admin", "n/a", "ROLE_ADMIN");
    }
}
