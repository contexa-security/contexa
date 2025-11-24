package io.contexa.contexaiam.admin.web.monitoring.controller;

import io.contexa.contexaiam.admin.web.monitoring.service.DashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@RequestMapping("/admin")
@RequiredArgsConstructor
public class DashboardController {

    private final DashboardService dashboardService;

    @GetMapping({"", "/", "/dashboard"})
    public String dashboard(Model model) {
        model.addAttribute("dashboardData", dashboardService.getDashboardData());
        model.addAttribute("activePage", "dashboard");
        return "admin/dashboard";
    }
}
