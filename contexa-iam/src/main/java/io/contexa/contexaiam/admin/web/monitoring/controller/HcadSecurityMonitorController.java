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

import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.HcadEvaluationExplanation;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.HcadSummary;
import io.contexa.contexaiam.admin.web.monitoring.service.HcadMonitoringService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Locale;

@Controller
@RequiredArgsConstructor
public class HcadSecurityMonitorController {

    private final HcadMonitoringService hcadMonitoringService;

    @GetMapping({
            "/contexa/admin/ai-monitor/hcad",
            "/contexa/admin/security-monitor/hcad"
    })
    public String page(
            @RequestParam(required = false, defaultValue = "day") String period,
            Model model) {
        model.addAttribute("activePage", "security-monitor-hcad");
        model.addAttribute("period", period);
        return "contexa/admin/security-monitor-hcad";
    }

    @ResponseBody
    @GetMapping({
            "/contexa/admin/api/security-monitor/hcad/summary",
            "/contexa/admin/api/ai-monitor/hcad"
    })
    public HcadSummary summary(@RequestParam(required = false, defaultValue = "day") String period) {
        return hcadMonitoringService.summarize(period);
    }

    @ResponseBody
    @GetMapping({
            "/contexa/admin/api/ai-monitor/hcad/evaluations/{evaluationId}/explanation",
            "/contexa/admin/api/security-monitor/hcad/evaluations/{evaluationId}/explanation"
    })
    public HcadEvaluationExplanation explanation(@PathVariable String evaluationId) {
        return hcadMonitoringService.explainEvaluation(evaluationId);
    }

    @GetMapping(value = "/contexa/admin/api/security-monitor/hcad/summary.csv", produces = "text/csv")
    public ResponseEntity<String> csv(
            @RequestParam(required = false, defaultValue = "day") String period,
            @RequestHeader(value = HttpHeaders.ACCEPT_LANGUAGE, required = false) String acceptLanguage,
            Locale locale) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/csv; charset=UTF-8"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"hcad-monitor-" + period + ".csv\"")
                .body(hcadMonitoringService.exportCsv(period, resolveLocale(locale, acceptLanguage)));
    }

    private Locale resolveLocale(Locale locale, String acceptLanguage) {
        if (acceptLanguage != null && acceptLanguage.toLowerCase(Locale.ROOT).contains("ko")) {
            return Locale.KOREAN;
        }
        return locale;
    }
}
