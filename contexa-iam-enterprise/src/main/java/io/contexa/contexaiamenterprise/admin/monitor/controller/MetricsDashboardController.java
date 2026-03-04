package io.contexa.contexaiamenterprise.admin.monitor.controller;

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
        model.addAttribute("pageTitle", "Executive Integrated Security Dashboard");
        model.addAttribute("activePage", "executive-overview");
        return "admin/executive-overview";
    }

    @GetMapping("/zerotrust-monitoring")
    public String zerotrustMonitoring(Model model) {
        model.addAttribute("pageTitle", "Zero Trust Real-time Monitoring");
        model.addAttribute("activePage", "zerotrust-monitoring");
        return "admin/zerotrust-monitoring";
    }

    @GetMapping("/evolution-learning")
    public String evolutionLearning(Model model) {
        model.addAttribute("pageTitle", "Evolution & Learning Detailed Metrics");
        model.addAttribute("activePage", "evolution-learning");
        return "admin/evolution-learning";
    }

    @GetMapping("/vectorstore-metrics")
    public String vectorstoreMetrics(Model model) {
        model.addAttribute("pageTitle", "VectorStore Monitoring");
        model.addAttribute("activePage", "vectorstore-metrics");
        return "admin/vectorstore-metrics";
    }

    @GetMapping("/tools-monitoring")
    public String toolsMonitoring(Model model) {
        model.addAttribute("pageTitle", "Tools Monitoring (MCP + SOAR)");
        model.addAttribute("activePage", "tools-monitoring");
        return "admin/tools-monitoring";
    }

    @GetMapping("/system-overview")
    public String systemOverview(Model model) {
        model.addAttribute("pageTitle", "System Overview");
        model.addAttribute("activePage", "system-overview");
        return "admin/system-overview";
    }
}
