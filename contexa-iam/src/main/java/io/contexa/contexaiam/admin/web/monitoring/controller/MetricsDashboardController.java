package io.contexa.contexaiam.admin.web.monitoring.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;


@Slf4j
@RequestMapping("/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class MetricsDashboardController {

    
    @GetMapping("/executive-overview")
    public String executiveOverview(Model model) {
        model.addAttribute("pageTitle", "임원진 통합 보안 대시보드");
        model.addAttribute("activePage", "executive-overview");
        return "admin/executive-overview";
    }

    
    @GetMapping("/zerotrust-monitoring")
    public String zerotrustMonitoring(Model model) {
        model.addAttribute("pageTitle", "제로트러스트 실시간 모니터링");
        model.addAttribute("activePage", "zerotrust-monitoring");
        return "admin/zerotrust-monitoring";
    }

    
    @GetMapping("/evolution-learning")
    public String evolutionLearning(Model model) {
        model.addAttribute("pageTitle", "Evolution & Learning 상세 메트릭");
        model.addAttribute("activePage", "evolution-learning");
        return "admin/evolution-learning";
    }

    
    @GetMapping("/vectorstore-metrics")
    public String vectorstoreMetrics(Model model) {
        model.addAttribute("pageTitle", "VectorStore 모니터링");
        model.addAttribute("activePage", "vectorstore-metrics");
        return "admin/vectorstore-metrics";
    }

    
    @GetMapping("/tools-monitoring")
    public String toolsMonitoring(Model model) {
        model.addAttribute("pageTitle", "Tools 모니터링 (MCP + SOAR)");
        model.addAttribute("activePage", "tools-monitoring");
        return "admin/tools-monitoring";
    }

    
    @GetMapping("/system-overview")
    public String systemOverview(Model model) {
        model.addAttribute("pageTitle", "시스템 개요");
        model.addAttribute("activePage", "system-overview");
        return "admin/system-overview";
    }
}
