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
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.FailureSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.LlmDecisionSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitoringResetRequest;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitoringResetResponse;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitoringSessionCurrent;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitoringSessionSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.OverviewSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.ReadinessSummary;
import io.contexa.contexaiam.admin.web.monitoring.service.AiSecurityDecisionMonitoringService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;
import java.util.List;
import java.util.Locale;

@Controller
@RequiredArgsConstructor
public class AiMonitorController {

    private final AiSecurityDecisionMonitoringService aiSecurityDecisionMonitoringService;

    @GetMapping({
            "/contexa/admin/ai-monitor",
            "/contexa/admin/ai-monitor/overview"
    })
    public String overviewPage(@RequestParam(required = false, defaultValue = "day") String period, Model model) {
        return page("overview", "ai-monitor-overview", "/contexa/admin/ai-monitor", period, model);
    }

    @GetMapping("/contexa/admin/ai-monitor/llm")
    public String llmPage(@RequestParam(required = false, defaultValue = "day") String period, Model model) {
        return page("llm", "ai-monitor-llm", "/contexa/admin/ai-monitor/llm", period, model);
    }

    @GetMapping("/contexa/admin/ai-monitor/correlation")
    public String correlationPage(@RequestParam(required = false, defaultValue = "day") String period, Model model) {
        return page("correlation", "ai-monitor-correlation", "/contexa/admin/ai-monitor/correlation", period, model);
    }

    @GetMapping({
            "/contexa/admin/ai-monitor/failures",
            "/contexa/admin/ai-monitor/operations"
    })
    public String failuresPage(@RequestParam(required = false, defaultValue = "day") String period, Model model) {
        return page("failures", "ai-monitor-failures", "/contexa/admin/ai-monitor/failures", period, model);
    }

    @GetMapping("/contexa/admin/ai-monitor/readiness")
    public String readinessPage(@RequestParam(required = false, defaultValue = "day") String period, Model model) {
        return page("readiness", "ai-monitor-readiness", "/contexa/admin/ai-monitor/readiness", period, model);
    }

    @ResponseBody
    @GetMapping("/contexa/admin/api/ai-monitor/overview")
    public OverviewSummary overview(@RequestParam(required = false, defaultValue = "day") String period) {
        return aiSecurityDecisionMonitoringService.overview(period);
    }

    @ResponseBody
    @GetMapping("/contexa/admin/api/ai-monitor/llm")
    public LlmDecisionSummary llm(@RequestParam(required = false, defaultValue = "day") String period) {
        return aiSecurityDecisionMonitoringService.llm(period);
    }

    @ResponseBody
    @GetMapping("/contexa/admin/api/ai-monitor/correlation")
    public CorrelationSummary correlation(@RequestParam(required = false, defaultValue = "day") String period) {
        return aiSecurityDecisionMonitoringService.correlation(period);
    }

    @ResponseBody
    @GetMapping("/contexa/admin/api/ai-monitor/failures")
    public FailureSummary failures(@RequestParam(required = false, defaultValue = "day") String period) {
        return aiSecurityDecisionMonitoringService.failures(period);
    }

    @ResponseBody
    @GetMapping("/contexa/admin/api/ai-monitor/readiness")
    public ReadinessSummary readiness(@RequestParam(required = false, defaultValue = "day") String period) {
        return aiSecurityDecisionMonitoringService.readiness(period);
    }


    @ResponseBody
    @GetMapping("/contexa/admin/api/ai-monitor/session/current")
    public MonitoringSessionCurrent currentSession(@RequestParam(required = false, defaultValue = "day") String period) {
        return aiSecurityDecisionMonitoringService.currentSession(period);
    }

    @ResponseBody
    @GetMapping("/contexa/admin/api/ai-monitor/session/summaries")
    public List<MonitoringSessionSummary> sessionSummaries() {
        return aiSecurityDecisionMonitoringService.sessionSummaries();
    }

    @ResponseBody
    @GetMapping("/contexa/admin/api/ai-monitor/session/summaries/{sessionId}")
    public ResponseEntity<MonitoringSessionSummary> sessionSummary(@PathVariable String sessionId) {
        MonitoringSessionSummary summary = aiSecurityDecisionMonitoringService.sessionSummary(sessionId);
        return summary == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(summary);
    }

    @ResponseBody
    @PostMapping("/contexa/admin/api/ai-monitor/reset")
    public MonitoringResetResponse resetMonitoring(
            @RequestBody(required = false) MonitoringResetRequest request,
            Principal principal) {
        String resetBy = principal == null ? null : principal.getName();
        return aiSecurityDecisionMonitoringService.resetMonitoring(request, resetBy);
    }
    @GetMapping(value = "/contexa/admin/api/ai-monitor/export.csv", produces = "text/csv")
    public ResponseEntity<String> exportCsv(
            @RequestParam(required = false, defaultValue = "day") String period,
            @RequestParam(required = false, defaultValue = "overview") String type,
            @RequestHeader(value = HttpHeaders.ACCEPT_LANGUAGE, required = false) String acceptLanguage,
            Locale locale) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/csv; charset=UTF-8"))
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"ai-monitor-" + type + "-" + period + ".csv\"")
                .body(aiSecurityDecisionMonitoringService.exportCsv(period, type, resolveLocale(locale, acceptLanguage)));
    }

    private String page(String section, String activePage, String pagePath, String period, Model model) {
        model.addAttribute("section", section);
        model.addAttribute("period", period == null || period.isBlank() ? "day" : period);
        model.addAttribute("activePage", activePage);
        model.addAttribute("pagePath", pagePath);
        return "contexa/admin/ai-monitor";
    }

    private Locale resolveLocale(Locale locale, String acceptLanguage) {
        if (acceptLanguage != null && acceptLanguage.toLowerCase(Locale.ROOT).contains("ko")) {
            return Locale.KOREAN;
        }
        return locale;
    }
}

